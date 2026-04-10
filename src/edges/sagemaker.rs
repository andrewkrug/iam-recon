use std::sync::Arc;

use crate::model::edge::Edge;
use crate::model::node::Node;
use crate::model::policy::Policy;
use crate::policy_eval::authorization::local_check_authorization_handling_mfa;
use crate::policy_eval::resource_policy;
use crate::util::case_insensitive_map::CaseInsensitiveMap;

pub fn generate_edges(nodes: &[Arc<Node>], scps: Option<&[Vec<&Policy>]>) -> Vec<Edge> {
    let mut edges = Vec::new();

    for dest in nodes {
        if !dest.is_role() {
            continue;
        }
        let trust_policy = match &dest.trust_policy {
            Some(tp) => tp,
            None => continue,
        };
        if !resource_policy::service_can_assume_role(trust_policy, "sagemaker.amazonaws.com") {
            continue;
        }

        for source in nodes {
            if source.arn == dest.arn || source.is_admin {
                continue;
            }

            let mut pass_ctx = CaseInsensitiveMap::new();
            pass_ctx.insert_single("iam:PassedToService", "sagemaker.amazonaws.com");
            let empty_ctx = CaseInsensitiveMap::new();

            let (can_pass, _) = local_check_authorization_handling_mfa(
                source,
                "iam:PassRole",
                &dest.arn,
                &pass_ctx,
                scps,
            );
            if !can_pass {
                continue;
            }

            // Check notebook instance
            let (can_notebook, _) = local_check_authorization_handling_mfa(
                source,
                "sagemaker:CreateNotebookInstance",
                "*",
                &empty_ctx,
                scps,
            );
            if can_notebook {
                edges.push(Edge::new(
                    &source.arn,
                    &dest.arn,
                    format!(
                        "{} can create a SageMaker notebook with {}",
                        source.searchable_name(),
                        dest.searchable_name()
                    ),
                    "SageMaker",
                ));
                continue;
            }

            // Check training job
            let (can_train, _) = local_check_authorization_handling_mfa(
                source,
                "sagemaker:CreateTrainingJob",
                "*",
                &empty_ctx,
                scps,
            );
            if can_train {
                edges.push(Edge::new(
                    &source.arn,
                    &dest.arn,
                    format!(
                        "{} can create a SageMaker training job with {}",
                        source.searchable_name(),
                        dest.searchable_name()
                    ),
                    "SageMaker",
                ));
                continue;
            }

            // Check processing job
            let (can_process, _) = local_check_authorization_handling_mfa(
                source,
                "sagemaker:CreateProcessingJob",
                "*",
                &empty_ctx,
                scps,
            );
            if can_process {
                edges.push(Edge::new(
                    &source.arn,
                    &dest.arn,
                    format!(
                        "{} can create a SageMaker processing job with {}",
                        source.searchable_name(),
                        dest.searchable_name()
                    ),
                    "SageMaker",
                ));
            }
        }
    }

    edges
}
