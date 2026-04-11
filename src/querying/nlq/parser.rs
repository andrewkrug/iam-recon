//! Recursive-descent parser. Supports boolean combinators, preset,
//! cypher-style `match`, `run <name>`, `what can <principal>`, and compare.

use std::collections::HashMap;

use super::ast::{BoolOp, Query};
use super::error::ParseError;
use super::lexer::{tokenize, Spanned, Token};
use super::synonyms;

pub fn parse(input: &str) -> Result<Query, ParseError> {
    let normalized = synonyms::normalize(input);
    let tokens = tokenize(&normalized);
    let mut p = Parser {
        source: input.to_string(),
        tokens,
        cursor: 0,
    };
    let q = p.parse_expr()?;
    p.expect_eof()?;
    Ok(q)
}

struct Parser {
    source: String,
    tokens: Vec<Spanned>,
    cursor: usize,
}

impl Parser {
    fn peek(&self) -> &Token {
        &self.tokens[self.cursor].token
    }
    fn peek_pos(&self) -> usize {
        self.tokens[self.cursor].pos
    }
    fn advance(&mut self) -> Token {
        let t = self.tokens[self.cursor].token.clone();
        if self.cursor + 1 < self.tokens.len() {
            self.cursor += 1;
        }
        t
    }
    fn expect_eof(&self) -> Result<(), ParseError> {
        if matches!(self.peek(), Token::Eof) {
            Ok(())
        } else {
            Err(ParseError::new(
                &self.source,
                self.peek_pos(),
                format!("unexpected trailing token: {:?}", self.peek()),
            ))
        }
    }
    fn err(&self, msg: impl Into<String>) -> ParseError {
        ParseError::new(&self.source, self.peek_pos(), msg)
    }

    /// Top-level expression: supports boolean combinators.
    ///   expr := atom (('and'|'or'|'but_not') atom)*
    fn parse_expr(&mut self) -> Result<Query, ParseError> {
        let mut left = self.parse_atom()?;
        loop {
            let op = match self.peek() {
                Token::And => Some(BoolOp::And),
                Token::Or => Some(BoolOp::Or),
                Token::ButNot => Some(BoolOp::Not),
                _ => None,
            };
            match op {
                Some(op) => {
                    self.advance();
                    let right = self.parse_atom()?;
                    left = Query::Bool {
                        op,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                }
                None => break,
            }
        }
        Ok(left)
    }

    /// atom := '(' expr ')' | who_q | can_q | preset_q | match_q | run_q | what_q | compare_q
    fn parse_atom(&mut self) -> Result<Query, ParseError> {
        match self.peek() {
            Token::LParen => {
                self.advance();
                let q = self.parse_expr()?;
                if !matches!(self.peek(), Token::RParen) {
                    return Err(self.err("expected ')'"));
                }
                self.advance();
                Ok(q)
            }
            Token::Who => self.parse_who(),
            Token::Can => self.parse_can(),
            Token::Preset => self.parse_preset(),
            Token::Match => self.parse_match(),
            Token::Run => self.parse_run(),
            Token::What => self.parse_what(),
            Token::Compare => self.parse_compare(),
            _ => Err(self.err(format!(
                "expected query start (who/can/preset/match/run/what/compare), got {:?}",
                self.peek()
            ))),
        }
    }

    /// who can do <action> [with <resource>] [when <conds>]
    /// who can reach admin
    /// who can assume <role>
    /// who can admin    (shorthand for 'has admin')
    fn parse_who(&mut self) -> Result<Query, ParseError> {
        self.advance(); // who
        if !matches!(self.peek(), Token::Can) {
            return Err(self.err("expected 'can' after 'who'"));
        }
        self.advance();

        // Shorthand: "who can admin" (from "who has admin")
        if let Token::Ident(s) = self.peek() {
            if s == "admin" {
                self.advance();
                return Ok(Query::Preset {
                    name: "wrongadmin".into(),
                    arg: None,
                });
            }
        }

        match self.peek() {
            Token::Reach => {
                self.advance();
                let target = self.expect_ident("expected target principal after 'reach'")?;
                Ok(Query::Can {
                    principal: "*".into(),
                    action: "sts:AssumeRole".into(),
                    resource: target,
                    conditions: HashMap::new(),
                })
            }
            Token::Assume => {
                self.advance();
                let target = self.expect_ident("expected role name after 'assume'")?;
                Ok(Query::Who {
                    action: "sts:AssumeRole".into(),
                    resource: target,
                    conditions: HashMap::new(),
                })
            }
            Token::Do => {
                self.advance();
                let action = self.expect_action_or_star("expected action after 'do'")?;
                let (resource, conds) = self.parse_with_when()?;
                Ok(Query::Who {
                    action,
                    resource,
                    conditions: conds,
                })
            }
            _ => Err(self.err("expected 'do', 'reach', 'assume', or 'admin' after 'who can'")),
        }
    }

    /// can <principal> do <action> [with <resource>] [when <conds>]
    fn parse_can(&mut self) -> Result<Query, ParseError> {
        self.advance(); // can
        let principal = self.expect_ident("expected principal name after 'can'")?;
        if !matches!(self.peek(), Token::Do) {
            return Err(self.err("expected 'do' after principal"));
        }
        self.advance();
        let action = self.expect_action_or_star("expected action after 'do'")?;
        let (resource, conds) = self.parse_with_when()?;
        Ok(Query::Can {
            principal,
            action,
            resource,
            conditions: conds,
        })
    }

    /// preset <name> [<arg>]
    fn parse_preset(&mut self) -> Result<Query, ParseError> {
        self.advance();
        let name = self.expect_ident("expected preset name")?;
        let arg = if let Token::Ident(_) | Token::Star = self.peek() {
            Some(self.expect_ident_or_star("expected preset arg")?)
        } else {
            None
        };
        Ok(Query::Preset { name, arg })
    }

    /// match <pattern>
    fn parse_match(&mut self) -> Result<Query, ParseError> {
        self.advance();
        // Collect all remaining tokens as raw text (before EOF or a boolean op)
        let mut parts = Vec::new();
        while !matches!(
            self.peek(),
            Token::Eof | Token::And | Token::Or | Token::ButNot | Token::RParen
        ) {
            parts.push(self.peek_as_raw());
            self.advance();
        }
        if parts.is_empty() {
            return Err(self.err("expected pattern after 'match'"));
        }
        Ok(Query::Pattern {
            text: parts.join(" "),
        })
    }

    fn peek_as_raw(&self) -> String {
        match self.peek() {
            Token::Ident(s) | Token::String(s) => s.clone(),
            Token::Star => "*".into(),
            Token::LParen => "(".into(),
            Token::RParen => ")".into(),
            t => format!("{:?}", t).to_lowercase(),
        }
    }

    /// run <saved_name>
    fn parse_run(&mut self) -> Result<Query, ParseError> {
        self.advance();
        let name = self.expect_ident("expected saved query name after 'run'")?;
        Ok(Query::Saved { name })
    }

    /// what can <principal>
    fn parse_what(&mut self) -> Result<Query, ParseError> {
        self.advance();
        // Optional "can"
        if matches!(self.peek(), Token::Can) {
            self.advance();
        }
        let principal = self.expect_ident("expected principal after 'what can'")?;
        // Optional "do" filler
        if matches!(self.peek(), Token::Do) {
            self.advance();
        }
        Ok(Query::What { principal })
    }

    /// compare <a> [and] <b>
    fn parse_compare(&mut self) -> Result<Query, ParseError> {
        self.advance();
        let a = self.expect_ident("expected first principal after 'compare'")?;
        if matches!(self.peek(), Token::And) {
            self.advance();
        }
        let b = self.expect_ident("expected second principal")?;
        Ok(Query::Compare { a, b })
    }

    fn parse_with_when(&mut self) -> Result<(String, HashMap<String, String>), ParseError> {
        let resource = if matches!(self.peek(), Token::With) {
            self.advance();
            self.expect_ident_or_star("expected resource after 'with'")?
        } else {
            "*".into()
        };

        let mut conds = HashMap::new();
        if matches!(self.peek(), Token::When) {
            self.advance();
            loop {
                let k = self.expect_ident("expected condition key after 'when'")?;
                if !matches!(self.peek(), Token::Is) {
                    return Err(self.err("expected 'is' after condition key"));
                }
                self.advance();
                let v = self.expect_ident_or_star("expected condition value")?;
                conds.insert(k, v);
                if matches!(self.peek(), Token::And) {
                    self.advance();
                    continue;
                }
                break;
            }
        }

        Ok((resource, conds))
    }

    fn expect_ident(&mut self, msg: &str) -> Result<String, ParseError> {
        match self.peek().clone() {
            Token::Ident(s) | Token::String(s) => {
                self.advance();
                Ok(s)
            }
            _ => Err(self.err(msg)),
        }
    }

    fn expect_ident_or_star(&mut self, msg: &str) -> Result<String, ParseError> {
        match self.peek().clone() {
            Token::Ident(s) | Token::String(s) => {
                self.advance();
                Ok(s)
            }
            Token::Star => {
                self.advance();
                Ok("*".into())
            }
            _ => Err(self.err(msg)),
        }
    }

    fn expect_action_or_star(&mut self, msg: &str) -> Result<String, ParseError> {
        // Accept "*" or "service:Action" or just a bare word
        self.expect_ident_or_star(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_who() {
        let q = parse("who can do iam:CreateUser with *").unwrap();
        match q {
            Query::Who {
                action, resource, ..
            } => {
                assert_eq!(action, "iam:createuser");
                assert_eq!(resource, "*");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_can() {
        let q = parse("can user/alice do s3:GetObject with *").unwrap();
        match q {
            Query::Can {
                principal, action, ..
            } => {
                assert_eq!(principal, "user/alice");
                assert_eq!(action, "s3:getobject");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_bool_and() {
        let q = parse("who can do iam:CreateUser and who can do iam:DeleteUser").unwrap();
        match q {
            Query::Bool {
                op: BoolOp::And, ..
            } => (),
            _ => panic!("expected bool AND"),
        }
    }

    #[test]
    fn test_parse_synonyms() {
        // "invoke" → "do", "on" → "with"
        let q = parse("who can invoke lambda:InvokeFunction on *").unwrap();
        match q {
            Query::Who {
                action, resource, ..
            } => {
                assert_eq!(action, "lambda:invokefunction");
                assert_eq!(resource, "*");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_conditions() {
        let q = parse("who can do s3:GetObject with * when aws:SourceIp is 10.0.0.0/8").unwrap();
        match q {
            Query::Who { conditions, .. } => {
                assert_eq!(
                    conditions.get("aws:sourceip"),
                    Some(&"10.0.0.0/8".to_string())
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_what() {
        let q = parse("what can user/alice").unwrap();
        match q {
            Query::What { principal } => assert_eq!(principal, "user/alice"),
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_run_saved() {
        let q = parse("run dangerous-s3").unwrap();
        match q {
            Query::Saved { name } => assert_eq!(name, "dangerous-s3"),
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_compare() {
        let q = parse("compare user/alice and user/bob").unwrap();
        match q {
            Query::Compare { a, b } => {
                assert_eq!(a, "user/alice");
                assert_eq!(b, "user/bob");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_reach() {
        // "who can reach admin" → can *:sts:AssumeRole with admin
        let q = parse("who can reach admin").unwrap();
        assert!(matches!(q, Query::Can { .. }));
    }

    #[test]
    fn test_parse_parens() {
        let q = parse("(who can do iam:CreateUser) and (who can do s3:PutObject)").unwrap();
        assert!(matches!(
            q,
            Query::Bool {
                op: BoolOp::And,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_error_position() {
        let e = parse("who can foo bar").unwrap_err();
        assert!(e.message.contains("expected 'do', 'reach'"));
    }
}
