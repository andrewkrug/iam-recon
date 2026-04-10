use std::sync::Arc;

use crate::error::Result;
use crate::model::edge::Edge;
use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::authorization::local_check_authorization_handling_mfa;
use crate::policy_eval::resource_policy;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

#[derive(Debug, Clone)]
pub struct CfnStack {
    pub stack_arn: String,
    pub role_arn: Option<String>,
}

pub async fn generate_edges(
    config: &aws_config::SdkConfig,
    nodes: &[Arc<Node>],
    scps: Option<&[Vec<&Policy>]>,
) -> Result<Vec<Edge>> {
    let client = aws_sdk_cloudformation::Client::new(config);
    let mut stacks = Vec::new();

    let mut paginator = client.describe_stacks().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = page.map_err(crate::error::aws_err)?;
        for s in page.stacks() {
            if let Some(arn) = s.stack_id() {
                stacks.push(CfnStack {
                    stack_arn: arn.to_string(),
                    role_arn: s.role_arn().map(|r| r.to_string()),
                });
            }
        }
    }

    Ok(generate_edges_locally(nodes, &stacks, scps))
}

pub fn generate_edges_locally(
    nodes: &[Arc<Node>],
    stacks: &[CfnStack],
    scps: Option<&[Vec<&Policy>]>,
) -> Vec<Edge> {
    let mut edges = Vec::new();

    for dest in nodes {
        if !dest.is_role() {
            continue;
        }

        let trust_policy = match &dest.trust_policy {
            Some(tp) => tp,
            None => continue,
        };
        if !resource_policy::service_can_assume_role(trust_policy, "cloudformation.amazonaws.com") {
            continue;
        }

        for source in nodes {
            if source.arn == dest.arn || source.is_admin {
                continue;
            }

            let mut pass_role_ctx = CaseInsensitiveMap::new();
            pass_role_ctx.insert_single("iam:PassedToService", "cloudformation.amazonaws.com");
            let empty_ctx = CaseInsensitiveMap::new();

            let (can_pass, _) = local_check_authorization_handling_mfa(
                source,
                "iam:PassRole",
                &dest.arn,
                &pass_role_ctx,
                scps,
            );
            if !can_pass {
                continue;
            }

            // Create new stack
            let (can_create, _) = local_check_authorization_handling_mfa(
                source,
                "cloudformation:CreateStack",
                "*",
                &empty_ctx,
                scps,
            );
            if can_create {
                edges.push(Edge::new(
                    &source.arn,
                    &dest.arn,
                    format!(
                        "{} can create a CloudFormation stack with {}",
                        source.searchable_name(),
                        dest.searchable_name()
                    ),
                    "CloudFormation",
                ));
                continue;
            }

            // Update existing stack with same role
            for stack in stacks {
                if stack.role_arn.as_deref() == Some(&dest.arn) {
                    let (can_update, _) = local_check_authorization_handling_mfa(
                        source,
                        "cloudformation:UpdateStack",
                        &stack.stack_arn,
                        &empty_ctx,
                        scps,
                    );
                    if can_update {
                        edges.push(Edge::new(
                            &source.arn,
                            &dest.arn,
                            format!(
                                "{} can update stack {} (uses {})",
                                source.searchable_name(),
                                stack.stack_arn,
                                dest.searchable_name()
                            ),
                            "CloudFormation",
                        ));
                        break;
                    }
                }
            }

            // Create and execute changeset
            let (can_create_cs, _) = local_check_authorization_handling_mfa(
                source,
                "cloudformation:CreateChangeSet",
                "*",
                &empty_ctx,
                scps,
            );
            let (can_execute_cs, _) = local_check_authorization_handling_mfa(
                source,
                "cloudformation:ExecuteChangeSet",
                "*",
                &empty_ctx,
                scps,
            );
            if can_create_cs && can_execute_cs {
                edges.push(Edge::new(
                    &source.arn,
                    &dest.arn,
                    format!(
                        "{} can create and execute a changeset with {}",
                        source.searchable_name(),
                        dest.searchable_name()
                    ),
                    "CloudFormation",
                ));
            }
        }
    }

    edges
}
