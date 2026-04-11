//! Tokenizer for normalized queries.

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Keywords
    Who,
    Can,
    Do,
    With,
    When,
    Is,
    And,
    Or,
    ButNot,
    Preset,
    Match,
    Run,
    Save,
    What,
    Compare,
    Reach,
    Assume,
    // Literal word (could be an action, principal, resource, value, or preset name)
    Ident(String),
    // Quoted string for resources with spaces
    String(String),
    // Wildcard
    Star,
    // Parens for grouping
    LParen,
    RParen,
    // End of input marker
    Eof,
}

impl Token {
    pub fn ident(&self) -> Option<&str> {
        match self {
            Token::Ident(s) | Token::String(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Spanned {
    pub token: Token,
    pub pos: usize,
}

pub fn tokenize(input: &str) -> Vec<Spanned> {
    let mut out = Vec::new();
    let mut chars = input.char_indices().peekable();

    while let Some(&(start, c)) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }

        if c == '(' {
            chars.next();
            out.push(Spanned {
                token: Token::LParen,
                pos: start,
            });
            continue;
        }
        if c == ')' {
            chars.next();
            out.push(Spanned {
                token: Token::RParen,
                pos: start,
            });
            continue;
        }
        if c == '*' {
            chars.next();
            out.push(Spanned {
                token: Token::Star,
                pos: start,
            });
            continue;
        }

        if c == '"' || c == '\'' {
            let quote = c;
            chars.next();
            let mut s = String::new();
            while let Some(&(_, ch)) = chars.peek() {
                if ch == quote {
                    chars.next();
                    break;
                }
                s.push(ch);
                chars.next();
            }
            out.push(Spanned {
                token: Token::String(s),
                pos: start,
            });
            continue;
        }

        // Ident: run until whitespace/paren/quote
        let mut s = String::new();
        while let Some(&(_, ch)) = chars.peek() {
            if ch.is_whitespace() || ch == '(' || ch == ')' {
                break;
            }
            s.push(ch);
            chars.next();
        }

        let token = match s.as_str() {
            "who" => Token::Who,
            "can" => Token::Can,
            "do" => Token::Do,
            "with" => Token::With,
            "when" => Token::When,
            "is" => Token::Is,
            "and" => Token::And,
            "or" => Token::Or,
            "but_not" | "butnot" | "except" => Token::ButNot,
            "preset" => Token::Preset,
            "match" => Token::Match,
            "run" => Token::Run,
            "save" => Token::Save,
            "what" => Token::What,
            "compare" => Token::Compare,
            "reach" => Token::Reach,
            "assume" => Token::Assume,
            _ => Token::Ident(s),
        };
        out.push(Spanned { token, pos: start });
    }

    out.push(Spanned {
        token: Token::Eof,
        pos: input.len(),
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tokenize() {
        let tokens = tokenize("who can do iam:CreateUser with *");
        let kinds: Vec<_> = tokens.iter().map(|t| &t.token).collect();
        assert_eq!(
            kinds,
            vec![
                &Token::Who,
                &Token::Can,
                &Token::Do,
                &Token::Ident("iam:CreateUser".into()),
                &Token::With,
                &Token::Star,
                &Token::Eof,
            ]
        );
    }

    #[test]
    fn test_quoted_string() {
        let tokens = tokenize(r#"who can do s3:GetObject with "arn with spaces""#);
        let kinds: Vec<_> = tokens.iter().map(|t| &t.token).collect();
        assert!(kinds.contains(&&Token::String("arn with spaces".into())));
    }

    #[test]
    fn test_parens() {
        let tokens = tokenize("(a) and (b)");
        assert_eq!(tokens[0].token, Token::LParen);
        assert_eq!(tokens[2].token, Token::RParen);
        assert_eq!(tokens[3].token, Token::And);
    }
}
