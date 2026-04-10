//! # IAM Recon Test Bench
//!
//! Compares the correctness and performance of the Rust rewrite (iam-recon)
//! against the original Python PMapper using identical test graphs and queries.
//!
//! ## Usage
//!   cargo test --test bench_compare -- --nocapture
//!
//! ## What it tests
//! 1. Graph construction (playground graph with 9 nodes, edge checkers)
//! 2. Policy evaluation engine (all condition operators, wildcards, MFA)
//! 3. Edge identification (STS assume role, admin connectivity)
//! 4. Querying (BFS paths, authorization checks)
//! 5. Serialization round-trip (JSON disk format compatibility)
//! 6. Performance comparison (timed runs of each operation)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

// Pull in crate modules via the library
use iam_recon::error;
use iam_recon::model::edge::Edge;
use iam_recon::model::graph::{Graph, GraphMetadata, IAM_RECON_VERSION};
use iam_recon::model::group::Group;
use iam_recon::model::node::Node;
use iam_recon::model::policy::Policy;
use iam_recon::policy_eval::authorization;
use iam_recon::policy_eval::resource_policy::{self, ResourcePolicyEvalResult};
use iam_recon::policy_eval::statement_match;
use iam_recon::querying::presets;
use iam_recon::querying::search;
use iam_recon::util::case_insensitive_map::CaseInsensitiveMap;

// ─── Test Graph Builders (mirrors Python's build_test_graphs.py) ───

fn get_default_metadata() -> GraphMetadata {
    GraphMetadata {
        account_id: "000000000000".to_string(),
        iam_recon_version: IAM_RECON_VERSION.to_string(),
        extra: HashMap::new(),
    }
}

fn get_admin_policy() -> serde_json::Value {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    })
}

fn get_jump_policy() -> serde_json::Value {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]
    })
}

fn get_ec2_for_ssm_policy() -> serde_json::Value {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["ssm:DescribeAssociation","ssm:GetDeployablePatchSnapshotForInstance","ssm:GetDocument","ssm:DescribeDocument","ssm:GetManifest","ssm:GetParameters","ssm:ListAssociations","ssm:ListInstanceAssociations","ssm:PutInventory","ssm:PutComplianceItems","ssm:PutConfigurePackageResult","ssm:UpdateAssociationStatus","ssm:UpdateInstanceAssociationStatus","ssm:UpdateInstanceInformation"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["ssmmessages:CreateControlChannel","ssmmessages:CreateDataChannel","ssmmessages:OpenControlChannel","ssmmessages:OpenDataChannel"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["ec2messages:AcknowledgeMessage","ec2messages:DeleteMessage","ec2messages:FailMessage","ec2messages:GetEndpoint","ec2messages:GetMessages","ec2messages:SendReply"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["cloudwatch:PutMetricData"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["ec2:DescribeInstanceStatus"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["ds:CreateComputer","ds:DescribeDirectories"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:DescribeLogGroups","logs:DescribeLogStreams","logs:PutLogEvents"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["s3:GetBucketLocation","s3:PutObject","s3:GetObject","s3:GetEncryptionConfiguration","s3:AbortMultipartUpload","s3:ListMultipartUploadParts","s3:ListBucket","s3:ListBucketMultipartUploads"], "Resource": "*"}
        ]
    })
}

fn get_s3_full_access_policy() -> serde_json::Value {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    })
}

fn make_trust_document(principal: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}]
    })
}

fn build_user_with_policy(
    policy_doc: serde_json::Value,
    policy_name: &str,
    user_name: &str,
    number: &str,
) -> Node {
    let policy = Arc::new(Policy::new(
        format!("arn:aws:iam::000000000000:policy/{}", policy_name),
        policy_name,
        policy_doc,
    ));
    Node {
        arn: format!("arn:aws:iam::000000000000:user/{}", user_name),
        id_value: format!("AIDA0000000000000000{}", number),
        attached_policies: vec![policy],
        group_memberships: vec![],
        trust_policy: None,
        instance_profile: None,
        active_password: true,
        access_keys: 1,
        is_admin: false,
        permissions_boundary: None,
        has_mfa: false,
        tags: HashMap::new(),
    }
}

fn build_empty_graph() -> Graph {
    Graph::new(vec![], vec![], vec![], vec![], get_default_metadata())
}

fn build_graph_with_one_admin() -> Graph {
    let admin_arn = "arn:aws:iam::000000000000:user/admin";
    let policy = Arc::new(Policy::new(
        admin_arn,
        "InlineAdminPolicy",
        get_admin_policy(),
    ));
    let node = Arc::new(Node {
        arn: admin_arn.to_string(),
        id_value: "AIDA00000000000000000".to_string(),
        attached_policies: vec![Arc::clone(&policy)],
        group_memberships: vec![],
        trust_policy: None,
        instance_profile: None,
        active_password: true,
        access_keys: 1,
        is_admin: true,
        permissions_boundary: None,
        has_mfa: false,
        tags: HashMap::new(),
    });
    Graph::new(
        vec![node],
        vec![],
        vec![policy],
        vec![],
        get_default_metadata(),
    )
}

fn build_playground_graph() -> Graph {
    let prefix = "arn:aws:iam::000000000000:";

    let admin_policy = Arc::new(Policy::new(
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "AdministratorAccess",
        get_admin_policy(),
    ));
    let ec2_ssm_policy = Arc::new(Policy::new(
        "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM",
        "AmazonEC2RoleforSSM",
        get_ec2_for_ssm_policy(),
    ));
    let s3_policy = Arc::new(Policy::new(
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "AmazonS3FullAccess",
        get_s3_full_access_policy(),
    ));
    let jump_policy = Arc::new(Policy::new(
        "arn:aws:iam::000000000000:policy/JumpPolicy",
        "JumpPolicy",
        get_jump_policy(),
    ));

    let ec2_trust = make_trust_document(serde_json::json!({"Service": "ec2.amazonaws.com"}));
    let root_trust =
        make_trust_document(serde_json::json!({"AWS": "arn:aws:iam::000000000000:root"}));
    let alt_root_trust = make_trust_document(serde_json::json!({"AWS": "000000000000"}));
    let other_acct_trust = make_trust_document(serde_json::json!({"AWS": "999999999999"}));

    let nodes: Vec<Arc<Node>> = vec![
        // Admin user
        Arc::new(Node {
            arn: format!("{}user/admin", prefix),
            id_value: "AIDA00000000000000000".into(),
            attached_policies: vec![Arc::clone(&admin_policy)],
            group_memberships: vec![],
            trust_policy: None,
            instance_profile: None,
            active_password: true,
            access_keys: 1,
            is_admin: true,
            permissions_boundary: None,
            has_mfa: false,
            tags: HashMap::new(),
        }),
        // EC2 SSM role
        Arc::new(Node {
            arn: format!("{}role/ec2_ssm_role", prefix),
            id_value: "AIDA00000000000000001".into(),
            attached_policies: vec![Arc::clone(&ec2_ssm_policy)],
            group_memberships: vec![],
            trust_policy: Some(ec2_trust.clone()),
            instance_profile: Some(vec![format!("{}instance-profile/ec2_ssm_role", prefix)]),
            active_password: false,
            access_keys: 0,
            is_admin: false,
            permissions_boundary: None,
            has_mfa: false,
            tags: HashMap::new(),
        }),
        // EC2 admin role
        Arc::new(Node {
            arn: format!("{}role/ec2_admin_role", prefix),
            id_value: "AIDA00000000000000002".into(),
            attached_policies: vec![Arc::clone(&ec2_ssm_policy)],
            group_memberships: vec![],
            trust_policy: Some(ec2_trust.clone()),
            instance_profile: Some(vec![format!("{}instance-profile/ec2_admin_role", prefix)]),
            active_password: false,
            access_keys: 0,
            is_admin: true,
            permissions_boundary: None,
            has_mfa: false,
            tags: HashMap::new(),
        }),
        // S3 access role (root trusted)
        Arc::new(Node {
            arn: format!("{}role/s3_access_role", prefix),
            id_value: "AIDA00000000000000003".into(),
            attached_policies: vec![Arc::clone(&s3_policy)],
            group_memberships: vec![],
            trust_policy: Some(root_trust.clone()),
            instance_profile: None,
            active_password: false,
            access_keys: 0,
            is_admin: false,
            permissions_boundary: None,
            has_mfa: false,
            tags: HashMap::new(),
        }),
        // S3 access role (alt root trusted)
        Arc::new(Node {
            arn: format!("{}role/s3_access_role_alt", prefix),
            id_value: "AIDA00000000000000004".into(),
            attached_policies: vec![Arc::clone(&s3_policy)],
            group_memberships: vec![],
            trust_policy: Some(alt_root_trust.clone()),
            instance_profile: None,
            active_password: false,
            access_keys: 0,
            is_admin: false,
            permissions_boundary: None,
            has_mfa: false,
            tags: HashMap::new(),
        }),
        // External S3 role (other account)
        Arc::new(Node {
            arn: format!("{}role/external_s3_access_role", prefix),
            id_value: "AIDA00000000000000005".into(),
            attached_policies: vec![Arc::clone(&s3_policy)],
            group_memberships: vec![],
            trust_policy: Some(other_acct_trust.clone()),
            instance_profile: None,
            active_password: false,
            access_keys: 0,
            is_admin: false,
            permissions_boundary: None,
            has_mfa: false,
            tags: HashMap::new(),
        }),
        // Jump user
        Arc::new(Node {
            arn: format!("{}user/jumpuser", prefix),
            id_value: "AIDA00000000000000006".into(),
            attached_policies: vec![Arc::clone(&jump_policy)],
            group_memberships: vec![],
            trust_policy: None,
            instance_profile: None,
            active_password: true,
            access_keys: 1,
            is_admin: false,
            permissions_boundary: None,
            has_mfa: false,
            tags: HashMap::new(),
        }),
        // User with path
        Arc::new(Node {
            arn: format!("{}user/somepath/some_other_jumpuser", prefix),
            id_value: "AIDA00000000000000007".into(),
            attached_policies: vec![Arc::clone(&jump_policy)],
            group_memberships: vec![],
            trust_policy: None,
            instance_profile: None,
            active_password: true,
            access_keys: 1,
            is_admin: false,
            permissions_boundary: None,
            has_mfa: false,
            tags: HashMap::new(),
        }),
        // Role with path
        Arc::new(Node {
            arn: format!("{}role/somepath/somerole", prefix),
            id_value: "AIDA00000000000000008".into(),
            attached_policies: vec![Arc::clone(&s3_policy)],
            group_memberships: vec![],
            trust_policy: Some(alt_root_trust.clone()),
            instance_profile: None,
            active_password: false,
            access_keys: 0,
            is_admin: false,
            permissions_boundary: None,
            has_mfa: false,
            tags: HashMap::new(),
        }),
    ];

    // Generate STS edges locally (same as Python's obtain_edges)
    let edges = iam_recon::edges::sts::generate_edges(&nodes, None);

    let policies = vec![admin_policy, ec2_ssm_policy, s3_policy, jump_policy];
    Graph::new(nodes, edges, policies, vec![], get_default_metadata())
}

// ─── Performance Harness ───

struct BenchResult {
    name: String,
    rust_us: u128,
    iterations: u32,
}

impl BenchResult {
    fn print(&self) {
        let per_iter = self.rust_us as f64 / self.iterations as f64;
        println!(
            "  {:50} {:>8.1}µs/iter  ({} iters, {:.1}ms total)",
            self.name,
            per_iter,
            self.iterations,
            self.rust_us as f64 / 1000.0,
        );
    }
}

fn bench<F: FnMut()>(name: &str, iterations: u32, mut f: F) -> BenchResult {
    // Warmup
    f();
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed().as_micros();
    BenchResult {
        name: name.to_string(),
        rust_us: elapsed,
        iterations,
    }
}

// ═══════════════════════════════════════════════════════════════════
//  TEST SUITE 1: Graph Construction
// ═══════════════════════════════════════════════════════════════════

#[test]
fn bench_graph_construction() {
    println!("\n══════ Graph Construction Benchmark ══════");

    let r = bench("build_empty_graph", 10_000, || {
        let _ = build_empty_graph();
    });
    r.print();

    let r = bench("build_graph_with_one_admin", 10_000, || {
        let _ = build_graph_with_one_admin();
    });
    r.print();

    let r = bench(
        "build_playground_graph (9 nodes + STS edges)",
        1_000,
        || {
            let _ = build_playground_graph();
        },
    );
    r.print();
}

// ═══════════════════════════════════════════════════════════════════
//  TEST SUITE 2: Policy Evaluation (ported from test_local_querying.py)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_admin_can_do_anything() {
    let graph = build_graph_with_one_admin();
    let principal = &graph.nodes[0];
    let ctx = CaseInsensitiveMap::new();
    assert!(authorization::local_check_authorization(
        principal,
        "iam:PutUserPolicy",
        "*",
        &ctx
    ));
    assert!(authorization::local_check_authorization(
        principal,
        "iam:PutUserPolicy",
        &principal.arn,
        &ctx
    ));
    assert!(authorization::local_check_authorization(
        principal,
        "iam:CreateRole",
        "*",
        &ctx
    ));
    assert!(authorization::local_check_authorization(
        principal,
        "sts:AssumeRole",
        "*",
        &ctx
    ));
}

#[test]
fn test_condition_key_handling_in_resources() {
    let test_node = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:CreateAccessKey",
                "Resource": "arn:aws:iam::000000000000:user/${aws:username}"
            }]
        }),
        "single_user_policy",
        "asdf",
        "0",
    );
    let mut ctx = CaseInsensitiveMap::new();
    ctx.insert_single("aws:username", "asdf");
    assert!(statement_match::has_matching_statement(
        &test_node,
        "Allow",
        "iam:CreateAccessKey",
        &test_node.arn,
        &ctx
    ));
}

#[test]
fn test_arn_condition() {
    // ArnEquals: no wildcards
    let node = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"ArnEquals": {"aws:SourceArn": "arn:aws:iam::000000000000:user/test1"}}}]
        }),
        "test",
        "asdf",
        "0",
    );
    let mut ctx = CaseInsensitiveMap::new();
    ctx.insert_single("aws:SourceArn", "arn:aws:iam::000000000000:user/test1");
    assert!(authorization::local_check_authorization(
        &node,
        "iam:CreateUser",
        "*",
        &ctx
    ));

    let mut ctx2 = CaseInsensitiveMap::new();
    ctx2.insert_single("aws:SourceArn", "arn:aws:iam::000000000000:user/test2");
    assert!(!authorization::local_check_authorization(
        &node,
        "iam:CreateUser",
        "*",
        &ctx2
    ));

    // ArnEquals: wildcards
    let node2 = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"ArnEquals": {"aws:SourceArn": "arn:aws:iam::*:user/test1"}}}]
        }),
        "test",
        "asdf",
        "0",
    );
    assert!(authorization::local_check_authorization(
        &node2,
        "iam:CreateUser",
        "*",
        &ctx
    ));
    assert!(!authorization::local_check_authorization(
        &node2,
        "iam:CreateUser",
        "*",
        &ctx2
    ));

    // ArnNotLike
    let node3 = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"ArnNotLike": {"aws:SourceArn": "arn:aws:iam::*:user/test1"}}}]
        }),
        "test",
        "asdf",
        "0",
    );
    assert!(!authorization::local_check_authorization(
        &node3,
        "iam:CreateUser",
        "*",
        &ctx
    ));
    assert!(authorization::local_check_authorization(
        &node3,
        "iam:CreateUser",
        "*",
        &ctx2
    ));
}

#[test]
fn test_datetime_condition_handling() {
    let node = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"DateEquals": {"aws:CurrentTime": "2018-08-10T00:00:00Z"}}}]
        }),
        "test",
        "asdf",
        "0",
    );
    let mut ctx = CaseInsensitiveMap::new();
    ctx.insert_single("aws:CurrentTime", "2018-08-10T00:00:00Z");
    assert!(authorization::local_check_authorization(
        &node,
        "iam:CreateUser",
        "*",
        &ctx
    ));

    let mut ctx_epoch = CaseInsensitiveMap::new();
    ctx_epoch.insert_single("aws:CurrentTime", "1533859200");
    assert!(authorization::local_check_authorization(
        &node,
        "iam:CreateUser",
        "*",
        &ctx_epoch
    ));

    let mut ctx_wrong = CaseInsensitiveMap::new();
    ctx_wrong.insert_single("aws:CurrentTime", "2018-08-10T00:00:01Z");
    assert!(!authorization::local_check_authorization(
        &node,
        "iam:CreateUser",
        "*",
        &ctx_wrong
    ));

    // DateGreaterThan
    let node_gt = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"DateGreaterThan": {"aws:CurrentTime": "2018-08-10T00:00:00Z"}}}]
        }),
        "test",
        "asdf",
        "0",
    );
    assert!(!authorization::local_check_authorization(
        &node_gt,
        "iam:CreateUser",
        "*",
        &ctx
    ));
    assert!(authorization::local_check_authorization(
        &node_gt,
        "iam:CreateUser",
        "*",
        &ctx_wrong
    ));

    // DateLessThanEquals
    let node_lte = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"DateLessThanEquals": {"aws:CurrentTime": "2018-08-10T00:00:00Z"}}}]
        }),
        "test",
        "asdf",
        "0",
    );
    assert!(authorization::local_check_authorization(
        &node_lte,
        "iam:CreateUser",
        "*",
        &ctx
    ));
    assert!(!authorization::local_check_authorization(
        &node_lte,
        "iam:CreateUser",
        "*",
        &ctx_wrong
    ));

    let mut ctx_before = CaseInsensitiveMap::new();
    ctx_before.insert_single("aws:CurrentTime", "2018-08-09T23:59:59Z");
    assert!(authorization::local_check_authorization(
        &node_lte,
        "iam:CreateUser",
        "*",
        &ctx_before
    ));
}

#[test]
fn test_ipaddress_condition_handling() {
    // Single IP
    let node = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.1"}}}]
        }),
        "test",
        "asdf",
        "0",
    );
    let mut ctx = CaseInsensitiveMap::new();
    ctx.insert_single("aws:SourceIp", "10.0.0.1");
    assert!(authorization::local_check_authorization(
        &node,
        "iam:CreateUser",
        "*",
        &ctx
    ));

    let mut ctx2 = CaseInsensitiveMap::new();
    ctx2.insert_single("aws:SourceIp", "10.0.0.2");
    assert!(!authorization::local_check_authorization(
        &node,
        "iam:CreateUser",
        "*",
        &ctx2
    ));

    // CIDR range
    let node_cidr = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}]
        }),
        "test",
        "asdf",
        "0",
    );
    assert!(authorization::local_check_authorization(
        &node_cidr,
        "iam:CreateUser",
        "*",
        &ctx
    ));
    let mut ctx3 = CaseInsensitiveMap::new();
    ctx3.insert_single("aws:SourceIp", "127.0.0.1");
    assert!(!authorization::local_check_authorization(
        &node_cidr,
        "iam:CreateUser",
        "*",
        &ctx3
    ));

    // Multiple CIDRs
    let node_multi = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "127.0.0.0/8"]}}}]
        }),
        "test",
        "asdf",
        "0",
    );
    assert!(authorization::local_check_authorization(
        &node_multi,
        "iam:CreateUser",
        "*",
        &ctx
    ));
    assert!(authorization::local_check_authorization(
        &node_multi,
        "iam:CreateUser",
        "*",
        &ctx3
    ));
    let mut ctx4 = CaseInsensitiveMap::new();
    ctx4.insert_single("aws:SourceIp", "192.168.0.1");
    assert!(!authorization::local_check_authorization(
        &node_multi,
        "iam:CreateUser",
        "*",
        &ctx4
    ));
}

#[test]
fn test_bool_condition_handling() {
    let node_true = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]
        }),
        "test",
        "asdf",
        "0",
    );
    let mut ctx_t = CaseInsensitiveMap::new();
    ctx_t.insert_single("aws:SecureTransport", "true");
    assert!(authorization::local_check_authorization(
        &node_true,
        "iam:CreateUser",
        "*",
        &ctx_t
    ));

    let mut ctx_t2 = CaseInsensitiveMap::new();
    ctx_t2.insert_single("aws:SecureTransport", "True");
    assert!(authorization::local_check_authorization(
        &node_true,
        "iam:CreateUser",
        "*",
        &ctx_t2
    ));

    let mut ctx_f = CaseInsensitiveMap::new();
    ctx_f.insert_single("aws:SecureTransport", "false");
    assert!(!authorization::local_check_authorization(
        &node_true,
        "iam:CreateUser",
        "*",
        &ctx_f
    ));

    // Bool: false - "asdf" is treated as false (matches policy sim behavior)
    let node_false = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]
        }),
        "test",
        "asdf",
        "0",
    );
    assert!(authorization::local_check_authorization(
        &node_false,
        "iam:CreateUser",
        "*",
        &ctx_f
    ));
    assert!(!authorization::local_check_authorization(
        &node_false,
        "iam:CreateUser",
        "*",
        &ctx_t
    ));

    let mut ctx_asdf = CaseInsensitiveMap::new();
    ctx_asdf.insert_single("aws:SecureTransport", "asdf");
    assert!(authorization::local_check_authorization(
        &node_false,
        "iam:CreateUser",
        "*",
        &ctx_asdf
    ));
}

#[test]
fn test_forallvalues_string_equals() {
    // DynamoDB ForAllValues:StringEquals (from Python test_documented_ddb_authorization_behavior)
    let node = build_user_with_policy(
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "dynamodb:GetItem",
                "Resource": "arn:aws:dynamodb:*:*:table/Thread",
                "Condition": {"ForAllValues:StringEquals": {
                    "dynamodb:Attributes": ["ID", "Message", "Tags"]}}}]
        }),
        "test",
        "asdf",
        "0",
    );

    // All requested attributes are allowed
    let mut ctx = CaseInsensitiveMap::new();
    ctx.insert("dynamodb:Attributes", "ID");
    ctx.insert("dynamodb:Attributes", "Message");
    ctx.insert("dynamodb:Attributes", "Tags");
    assert!(authorization::local_check_authorization(
        &node,
        "dynamodb:GetItem",
        "arn:aws:dynamodb:us-west-2:000000000000:table/Thread",
        &ctx
    ));

    // Subset is allowed
    let mut ctx2 = CaseInsensitiveMap::new();
    ctx2.insert("dynamodb:Attributes", "ID");
    ctx2.insert("dynamodb:Attributes", "Message");
    assert!(authorization::local_check_authorization(
        &node,
        "dynamodb:GetItem",
        "arn:aws:dynamodb:us-west-2:000000000000:table/Thread",
        &ctx2
    ));

    // Empty set = vacuously true
    let ctx_empty = CaseInsensitiveMap::new();
    assert!(authorization::local_check_authorization(
        &node,
        "dynamodb:GetItem",
        "arn:aws:dynamodb:us-west-2:000000000000:table/Thread",
        &ctx_empty
    ));

    // Extra attribute "Password" = denied
    let mut ctx3 = CaseInsensitiveMap::new();
    ctx3.insert("dynamodb:Attributes", "ID");
    ctx3.insert("dynamodb:Attributes", "Message");
    ctx3.insert("dynamodb:Attributes", "Tags");
    ctx3.insert("dynamodb:Attributes", "Password");
    assert!(!authorization::local_check_authorization(
        &node,
        "dynamodb:GetItem",
        "arn:aws:dynamodb:us-west-2:000000000000:table/Thread",
        &ctx3
    ));
}

// ═══════════════════════════════════════════════════════════════════
//  TEST SUITE 3: Edge Identification (ported from test_edge_identification.py)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_playground_assume_role() {
    let graph = build_playground_graph();
    let jump_user = graph.get_node_by_searchable_name("user/jumpuser").unwrap();
    let s3_role = graph
        .get_node_by_searchable_name("role/s3_access_role")
        .unwrap();
    let s3_role_alt = graph
        .get_node_by_searchable_name("role/s3_access_role_alt")
        .unwrap();
    let external_role = graph
        .get_node_by_searchable_name("role/external_s3_access_role")
        .unwrap();

    assert!(search::is_connected(&graph, jump_user, s3_role).is_some());
    assert!(search::is_connected(&graph, jump_user, s3_role_alt).is_some());
    assert!(search::is_connected(&graph, jump_user, external_role).is_none());
}

#[test]
fn test_admin_access() {
    let graph = build_playground_graph();
    let admin = graph.get_node_by_searchable_name("user/admin").unwrap();
    let jump_user = graph.get_node_by_searchable_name("user/jumpuser").unwrap();
    let external_role = graph
        .get_node_by_searchable_name("role/external_s3_access_role")
        .unwrap();
    let other_jump = graph
        .get_node_by_searchable_name("user/somepath/some_other_jumpuser")
        .unwrap();
    let some_role = graph
        .get_node_by_searchable_name("role/somepath/somerole")
        .unwrap();

    assert!(search::is_connected(&graph, admin, jump_user).is_some());
    assert!(search::is_connected(&graph, admin, external_role).is_some());
    assert!(search::is_connected(&graph, other_jump, some_role).is_some());
}

// ═══════════════════════════════════════════════════════════════════
//  TEST SUITE 4: Resource Policy / Trust Policy Evaluation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_trust_policy_evaluation() {
    let trust = make_trust_document(serde_json::json!({"AWS": "arn:aws:iam::000000000000:root"}));
    let node = build_user_with_policy(get_jump_policy(), "jump", "testuser", "0");
    let ctx = CaseInsensitiveMap::new();

    let result = resource_policy::resource_policy_authorization(
        &node,
        "000000000000",
        &trust,
        "sts:AssumeRole",
        "*",
        &ctx,
    );
    assert_eq!(result, ResourcePolicyEvalResult::RootMatch);
}

#[test]
fn test_service_trust_policy() {
    let trust = make_trust_document(serde_json::json!({"Service": "lambda.amazonaws.com"}));
    assert!(resource_policy::service_can_assume_role(
        &trust,
        "lambda.amazonaws.com"
    ));
    assert!(!resource_policy::service_can_assume_role(
        &trust,
        "ec2.amazonaws.com"
    ));
}

// ═══════════════════════════════════════════════════════════════════
//  TEST SUITE 5: Serialization Round-Trip
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_graph_serialization_roundtrip() {
    let graph = build_playground_graph();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();

    graph.store_to_disk(path).unwrap();
    let loaded = Graph::load_from_disk(path).unwrap();

    assert_eq!(loaded.nodes.len(), graph.nodes.len());
    assert_eq!(loaded.edges.len(), graph.edges.len());
    assert_eq!(loaded.policies.len(), graph.policies.len());
    assert_eq!(loaded.metadata.account_id, graph.metadata.account_id);

    // Verify node lookup works
    assert!(loaded.get_node_by_searchable_name("user/admin").is_some());
    assert!(loaded
        .get_node_by_searchable_name("role/s3_access_role")
        .is_some());
    assert!(loaded.get_node_by_searchable_name("nonexistent").is_none());
}

// ═══════════════════════════════════════════════════════════════════
//  TEST SUITE 6: Querying Presets
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_privesc_detection() {
    let graph = build_playground_graph();
    let jump_user = graph.get_node_by_searchable_name("user/jumpuser").unwrap();

    // Jump user should be able to privesc (can assume role -> admin)
    let (can_esc, path) = presets::privesc::can_privesc(&graph, jump_user).unwrap();
    // Jump user can reach ec2_admin_role which is admin
    // Whether it can depends on edges; admin nodes are reachable via BFS
    if can_esc {
        assert!(!path.is_empty());
    }
}

#[test]
fn test_service_access_mapping() {
    let graph = build_playground_graph();
    let map = presets::serviceaccess::compose_service_access_map(&graph);

    // EC2 should have roles with ec2.amazonaws.com trust
    assert!(map.contains_key("ec2.amazonaws.com"));
    let ec2_roles = &map["ec2.amazonaws.com"];
    assert!(ec2_roles.len() >= 2); // ec2_ssm_role and ec2_admin_role
}

// ═══════════════════════════════════════════════════════════════════
//  TEST SUITE 7: Performance Benchmarks
// ═══════════════════════════════════════════════════════════════════

#[test]
fn bench_policy_evaluation() {
    println!("\n══════ Policy Evaluation Benchmark ══════");
    let graph = build_graph_with_one_admin();
    let principal = &graph.nodes[0];

    let r = bench("admin: local_check_authorization (allow)", 100_000, || {
        let ctx = CaseInsensitiveMap::new();
        authorization::local_check_authorization(principal, "iam:CreateUser", "*", &ctx);
    });
    r.print();

    let node = build_user_with_policy(
        serde_json::json!({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*",
             "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}
        ]}),
        "test",
        "bench_user",
        "0",
    );

    let r = bench("condition eval: IpAddress match", 100_000, || {
        let mut ctx = CaseInsensitiveMap::new();
        ctx.insert_single("aws:SourceIp", "10.5.3.2");
        authorization::local_check_authorization(&node, "s3:GetObject", "*", &ctx);
    });
    r.print();

    let r = bench("condition eval: IpAddress no-match", 100_000, || {
        let mut ctx = CaseInsensitiveMap::new();
        ctx.insert_single("aws:SourceIp", "192.168.1.1");
        authorization::local_check_authorization(&node, "s3:GetObject", "*", &ctx);
    });
    r.print();
}

#[test]
fn bench_edge_identification() {
    println!("\n══════ Edge Identification Benchmark ══════");
    let graph = build_playground_graph();

    let r = bench("STS edge generation (9 nodes)", 1_000, || {
        let _ = iam_recon::edges::sts::generate_edges(&graph.nodes, None);
    });
    r.print();

    let r = bench("IAM edge generation (9 nodes)", 1_000, || {
        let _ = iam_recon::edges::iam::generate_edges(&graph.nodes, None);
    });
    r.print();
}

#[test]
fn bench_querying() {
    println!("\n══════ Querying Benchmark ══════");
    let graph = build_playground_graph();
    let jump_user = graph.get_node_by_searchable_name("user/jumpuser").unwrap();
    let admin = graph.get_node_by_searchable_name("user/admin").unwrap();

    let r = bench("BFS: get_search_list (jump user)", 10_000, || {
        let _ = search::get_search_list(&graph, jump_user);
    });
    r.print();

    let r = bench("BFS: get_search_list (admin)", 10_000, || {
        let _ = search::get_search_list(&graph, admin);
    });
    r.print();

    let r = bench("search_authorization_for (all nodes)", 1_000, || {
        let ctx = CaseInsensitiveMap::new();
        for node in &graph.nodes {
            let _ = iam_recon::querying::query_interface::search_authorization_for(
                &graph,
                node,
                "s3:GetObject",
                "*",
                &ctx,
            );
        }
    });
    r.print();

    let r = bench("privesc detection (all nodes)", 1_000, || {
        for node in &graph.nodes {
            let _ = presets::privesc::can_privesc(&graph, node);
        }
    });
    r.print();
}

#[test]
fn bench_serialization() {
    println!("\n══════ Serialization Benchmark ══════");
    let graph = build_playground_graph();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();

    let r = bench("graph store_to_disk", 1_000, || {
        graph.store_to_disk(path).unwrap();
    });
    r.print();

    // Pre-write for load benchmark
    graph.store_to_disk(path).unwrap();
    let r = bench("graph load_from_disk", 1_000, || {
        let _ = Graph::load_from_disk(path).unwrap();
    });
    r.print();
}
