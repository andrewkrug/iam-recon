use std::sync::Arc;

use crate::error::Result;
use crate::model::edge::Edge;
use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::authorization::local_check_authorization_handling_mfa;
use crate::policy_eval::resource_policy;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

/// CodeBuild project info for edge checking
#[derive(Debug, Clone)]
pub struct CodeBuildProject {
    pub project_arn: String,
    pub service_role_arn: String,
}

/// Generate edges using AWS API
pub async fn generate_edges(
    config: &aws_config::SdkConfig,
    nodes: &[Arc<Node>],
    scps: Option<&[Vec<&Policy>]>,
) -> Result<Vec<Edge>> {
    let client = aws_sdk_codebuild::Client::new(config);
    let mut projects = Vec::new();

    // List project names
    let mut names = Vec::new();
    let mut paginator = client.list_projects().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = page.map_err(crate::error::aws_err)?;
        names.extend(page.projects().iter().map(|s| s.to_string()));
    }

    // Batch get project details
    for chunk in names.chunks(100) {
        let resp = client
            .batch_get_projects()
            .set_names(Some(chunk.to_vec()))
            .send()
            .await
            .map_err(crate::error::aws_err)?;
        for p in resp.projects() {
            if let (Some(arn), Some(role)) = (p.arn(), p.service_role()) {
                projects.push(CodeBuildProject {
                    project_arn: arn.to_string(),
                    service_role_arn: role.to_string(),
                });
            }
        }
    }

    Ok(generate_edges_locally(nodes, &projects, scps))
}

/// Generate edges from pre-fetched project data
pub fn generate_edges_locally(
    nodes: &[Arc<Node>],
    projects: &[CodeBuildProject],
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
        if !resource_policy::service_can_assume_role(trust_policy, "codebuild.amazonaws.com") {
            continue;
        }

        for source in nodes {
            if source.arn == dest.arn || source.is_admin {
                continue;
            }

            let mut pass_role_ctx = CaseInsensitiveMap::new();
            pass_role_ctx.insert_single("iam:PassedToService", "codebuild.amazonaws.com");
            let empty_ctx = CaseInsensitiveMap::new();

            // Check: start build on existing project with dest role
            for proj in projects {
                if proj.service_role_arn == dest.arn {
                    let (can_start, _) = local_check_authorization_handling_mfa(
                        source,
                        "codebuild:StartBuild",
                        &proj.project_arn,
                        &empty_ctx,
                        scps,
                    );
                    if can_start {
                        edges.push(Edge::new(
                            &source.arn,
                            &dest.arn,
                            format!(
                                "{} can start builds on {} (uses {})",
                                source.searchable_name(),
                                proj.project_arn,
                                dest.searchable_name()
                            ),
                            "CodeBuild",
                        ));
                        break;
                    }
                }
            }

            // Check: create new project with dest role
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

            let (can_create, _) = local_check_authorization_handling_mfa(
                source,
                "codebuild:CreateProject",
                "*",
                &empty_ctx,
                scps,
            );
            let (can_start, _) = local_check_authorization_handling_mfa(
                source,
                "codebuild:StartBuild",
                "*",
                &empty_ctx,
                scps,
            );

            if can_create && can_start {
                edges.push(Edge::new(
                    &source.arn,
                    &dest.arn,
                    format!(
                        "{} can create a CodeBuild project with {} and start a build",
                        source.searchable_name(),
                        dest.searchable_name()
                    ),
                    "CodeBuild",
                ));
                continue;
            }

            // Check: update existing project to use dest role
            for proj in projects {
                let (can_update, _) = local_check_authorization_handling_mfa(
                    source,
                    "codebuild:UpdateProject",
                    &proj.project_arn,
                    &empty_ctx,
                    scps,
                );
                let (can_start2, _) = local_check_authorization_handling_mfa(
                    source,
                    "codebuild:StartBuild",
                    &proj.project_arn,
                    &empty_ctx,
                    scps,
                );
                if can_update && can_start2 {
                    edges.push(Edge::new(
                        &source.arn,
                        &dest.arn,
                        format!(
                            "{} can update {} to use {} and start a build",
                            source.searchable_name(),
                            proj.project_arn,
                            dest.searchable_name()
                        ),
                        "CodeBuild",
                    ));
                    break;
                }
            }
        }
    }

    edges
}
