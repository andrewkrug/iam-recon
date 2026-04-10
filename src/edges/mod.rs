pub mod autoscaling;
pub mod cloudformation;
pub mod codebuild;
pub mod ec2;
pub mod iam;
pub mod lambda;
pub mod sagemaker;
pub mod ssm;
pub mod sts;

use std::sync::Arc;

use crate::error::Result;
use crate::model::edge::Edge;
use crate::model::node::Node;
use crate::model::policy::Policy;

/// Identifies which edge checkers to run
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckerKind {
    Iam,
    Sts,
    Lambda,
    Ec2,
    CodeBuild,
    CloudFormation,
    AutoScaling,
    Ssm,
    SageMaker,
}

impl CheckerKind {
    pub fn all() -> &'static [CheckerKind] {
        &[
            CheckerKind::Iam,
            CheckerKind::Sts,
            CheckerKind::Lambda,
            CheckerKind::Ec2,
            CheckerKind::CodeBuild,
            CheckerKind::CloudFormation,
            CheckerKind::AutoScaling,
            CheckerKind::Ssm,
            CheckerKind::SageMaker,
        ]
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "iam" => Some(Self::Iam),
            "sts" => Some(Self::Sts),
            "lambda" => Some(Self::Lambda),
            "ec2" => Some(Self::Ec2),
            "codebuild" => Some(Self::CodeBuild),
            "cloudformation" => Some(Self::CloudFormation),
            "autoscaling" => Some(Self::AutoScaling),
            "ssm" => Some(Self::Ssm),
            "sagemaker" => Some(Self::SageMaker),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Iam => "iam",
            Self::Sts => "sts",
            Self::Lambda => "lambda",
            Self::Ec2 => "ec2",
            Self::CodeBuild => "codebuild",
            Self::CloudFormation => "cloudformation",
            Self::AutoScaling => "autoscaling",
            Self::Ssm => "ssm",
            Self::SageMaker => "sagemaker",
        }
    }
}

/// Run all specified edge checkers and return combined edges.
/// For checkers that need AWS API calls, pass an sdk_config.
/// For offline-only operation, pass None.
pub async fn obtain_edges(
    sdk_config: Option<&aws_config::SdkConfig>,
    checkers: &[CheckerKind],
    nodes: &[Arc<Node>],
    _region_allow_list: Option<&[String]>,
    _region_deny_list: Option<&[String]>,
    scps: Option<&[Vec<&Policy>]>,
) -> Result<Vec<Edge>> {
    let mut all_edges = Vec::new();

    for checker in checkers {
        tracing::info!("Running edge checker: {}", checker.name());
        let edges = match checker {
            CheckerKind::Iam => iam::generate_edges(nodes, scps),
            CheckerKind::Sts => sts::generate_edges(nodes, scps),
            CheckerKind::Ec2 => ec2::generate_edges(nodes, scps),
            CheckerKind::Ssm => ssm::generate_edges(nodes, scps),
            CheckerKind::AutoScaling => autoscaling::generate_edges(nodes, scps),
            CheckerKind::SageMaker => sagemaker::generate_edges(nodes, scps),
            CheckerKind::Lambda => {
                if let Some(config) = sdk_config {
                    lambda::generate_edges(config, nodes, scps).await?
                } else {
                    lambda::generate_edges_locally(nodes, &[], scps)
                }
            }
            CheckerKind::CodeBuild => {
                if let Some(config) = sdk_config {
                    codebuild::generate_edges(config, nodes, scps).await?
                } else {
                    codebuild::generate_edges_locally(nodes, &[], scps)
                }
            }
            CheckerKind::CloudFormation => {
                if let Some(config) = sdk_config {
                    cloudformation::generate_edges(config, nodes, scps).await?
                } else {
                    cloudformation::generate_edges_locally(nodes, &[], scps)
                }
            }
        };
        tracing::info!("  {} edges found by {}", edges.len(), checker.name());
        all_edges.extend(edges);
    }

    Ok(all_edges)
}
