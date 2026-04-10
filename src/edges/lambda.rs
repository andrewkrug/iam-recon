use std::sync::Arc;

use crate::error::Result;
use crate::model::edge::Edge;
use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::authorization::local_check_authorization_handling_mfa;
use crate::policy_eval::resource_policy;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// Lambda function info needed for edge checking
#[derive(Debug, Clone)]
pub struct LambdaFunction {
    pub function_arn: String,
    pub role_arn: String,
}

/// Generate edges using AWS API to list Lambda functions
pub async fn generate_edges(
    config: &aws_config::SdkConfig,
    nodes: &[Arc<Node>],
    scps: Option<&[Vec<&Policy>]>,
) -> Result<Vec<Edge>> {
    let client = aws_sdk_lambda::Client::new(config);
    let mut functions = Vec::new();

    let mut paginator = client.list_functions().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = page.map_err(crate::error::aws_err)?;
        for f in page.functions() {
            if let (Some(arn), Some(role)) = (f.function_arn(), f.role()) {
                functions.push(LambdaFunction {
                    function_arn: arn.to_string(),
                    role_arn: role.to_string(),
                });
            }
        }
    }

    Ok(generate_edges_locally(nodes, &functions, scps))
}

/// Generate edges from pre-fetched Lambda function data
pub fn generate_edges_locally(
    nodes: &[Arc<Node>],
    functions: &[LambdaFunction],
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
        if !resource_policy::service_can_assume_role(trust_policy, "lambda.amazonaws.com") {
            continue;
        }

        for source in nodes {
            if source.arn == dest.arn || source.is_admin {
                continue;
            }

            let mut pass_role_ctx = CaseInsensitiveMap::new();
            pass_role_ctx.insert_single("iam:PassedToService", "lambda.amazonaws.com");

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

            let empty_ctx = CaseInsensitiveMap::new();

            // Check: create new function + invoke
            let (can_create, _) = local_check_authorization_handling_mfa(
                source,
                "lambda:CreateFunction",
                "*",
                &empty_ctx,
                scps,
            );
            let (can_invoke, _) = local_check_authorization_handling_mfa(
                source,
                "lambda:InvokeFunction",
                "*",
                &empty_ctx,
                scps,
            );

            if can_create && can_invoke {
                edges.push(Edge::new(
                    &source.arn,
                    &dest.arn,
                    format!(
                        "{} can create a Lambda function with {} and invoke it",
                        source.searchable_name(),
                        dest.searchable_name()
                    ),
                    "Lambda",
                ));
                continue;
            }

            // Check: update existing function code that uses dest role
            for func in functions {
                if func.role_arn == dest.arn {
                    let (can_update, _) = local_check_authorization_handling_mfa(
                        source,
                        "lambda:UpdateFunctionCode",
                        &func.function_arn,
                        &empty_ctx,
                        scps,
                    );
                    if can_update && can_invoke {
                        edges.push(Edge::new(
                            &source.arn,
                            &dest.arn,
                            format!(
                                "{} can update the code of Lambda function {} (with {}) and invoke it",
                                source.searchable_name(), func.function_arn, dest.searchable_name()
                            ),
                            "Lambda",
                        ));
                        break;
                    }
                }
            }

            // Check: update function config to change role + invoke
            for func in functions {
                let (can_update_config, _) = local_check_authorization_handling_mfa(
                    source,
                    "lambda:UpdateFunctionConfiguration",
                    &func.function_arn,
                    &empty_ctx,
                    scps,
                );
                if can_update_config && can_invoke {
                    edges.push(Edge::new(
                        &source.arn,
                        &dest.arn,
                        format!(
                            "{} can update the config of {} to use {} and invoke it",
                            source.searchable_name(),
                            func.function_arn,
                            dest.searchable_name()
                        ),
                        "Lambda",
                    ));
                    break;
                }
            }
        }
    }

    edges
}
