use crate::error::{self, Result};
use crate::model::policy::Policy;

/// Fetch S3 bucket policies
pub async fn get_s3_bucket_policies(config: &aws_config::SdkConfig) -> Result<Vec<Policy>> {
    let client = aws_sdk_s3::Client::new(config);
    let mut policies = Vec::new();

    let resp = client.list_buckets().send().await.map_err(error::aws_err)?;
    for bucket in resp.buckets() {
        let name = bucket.name().unwrap_or_default();
        let arn = format!("arn:aws:s3:::{}", name);

        match client.get_bucket_policy().bucket(name).send().await {
            Ok(policy_resp) => {
                if let Some(doc) = policy_resp.policy() {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(doc) {
                        policies.push(Policy::new(&arn, format!("{}-policy", name), parsed));
                    }
                }
            }
            Err(_) => {} // No bucket policy = skip
        }
    }

    Ok(policies)
}

/// Fetch SNS topic policies
pub async fn get_sns_topic_policies(config: &aws_config::SdkConfig) -> Result<Vec<Policy>> {
    let client = aws_sdk_sns::Client::new(config);
    let mut policies = Vec::new();

    let mut paginator = client.list_topics().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = page.map_err(error::aws_err)?;
        for topic in page.topics() {
            if let Some(arn) = topic.topic_arn() {
                match client.get_topic_attributes().topic_arn(arn).send().await {
                    Ok(attrs) => {
                        if let Some(policy_str) = attrs.attributes().and_then(|a| a.get("Policy")) {
                            if let Ok(parsed) =
                                serde_json::from_str::<serde_json::Value>(policy_str)
                            {
                                policies.push(Policy::new(arn, format!("{}-policy", arn), parsed));
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }

    Ok(policies)
}

/// Fetch SQS queue policies
pub async fn get_sqs_queue_policies(config: &aws_config::SdkConfig) -> Result<Vec<Policy>> {
    let client = aws_sdk_sqs::Client::new(config);
    let mut policies = Vec::new();

    let resp = client.list_queues().send().await.map_err(error::aws_err)?;
    for url in resp.queue_urls() {
        match client
            .get_queue_attributes()
            .queue_url(url)
            .attribute_names(aws_sdk_sqs::types::QueueAttributeName::Policy)
            .send()
            .await
        {
            Ok(attrs) => {
                if let Some(policy_str) = attrs
                    .attributes()
                    .and_then(|a| a.get(&aws_sdk_sqs::types::QueueAttributeName::Policy))
                {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(policy_str) {
                        // Extract ARN from attributes or construct from URL
                        let arn = attrs
                            .attributes()
                            .and_then(|a| a.get(&aws_sdk_sqs::types::QueueAttributeName::QueueArn))
                            .cloned()
                            .unwrap_or_else(|| url.clone());
                        policies.push(Policy::new(arn, "sqs-policy", parsed));
                    }
                }
            }
            Err(_) => {}
        }
    }

    Ok(policies)
}

/// Fetch KMS key policies
pub async fn get_kms_key_policies(config: &aws_config::SdkConfig) -> Result<Vec<Policy>> {
    let client = aws_sdk_kms::Client::new(config);
    let mut policies = Vec::new();

    let mut paginator = client.list_keys().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = page.map_err(error::aws_err)?;
        for key in page.keys() {
            if let Some(key_id) = key.key_id() {
                let arn = key.key_arn().unwrap_or(key_id);
                match client
                    .get_key_policy()
                    .key_id(key_id)
                    .policy_name("default")
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if let Some(doc) = resp.policy() {
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(doc) {
                                policies.push(Policy::new(arn, "kms-key-policy", parsed));
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }

    Ok(policies)
}

/// Fetch Secrets Manager resource policies
pub async fn get_secrets_manager_policies(config: &aws_config::SdkConfig) -> Result<Vec<Policy>> {
    let client = aws_sdk_secretsmanager::Client::new(config);
    let mut policies = Vec::new();

    let mut paginator = client.list_secrets().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = page.map_err(error::aws_err)?;
        for secret in page.secret_list() {
            if let Some(arn) = secret.arn() {
                match client.get_resource_policy().secret_id(arn).send().await {
                    Ok(resp) => {
                        if let Some(doc) = resp.resource_policy() {
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(doc) {
                                policies.push(Policy::new(arn, "secrets-manager-policy", parsed));
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }

    Ok(policies)
}
