//! Pre-written question templates surfaced in help output and the TUI.

pub struct QueryTemplate {
    pub question: &'static str,
    pub canonical: &'static str,
    pub description: &'static str,
}

pub const TEMPLATES: &[QueryTemplate] = &[
    QueryTemplate {
        question: "Who has admin?",
        canonical: "preset wrongadmin",
        description: "List all principals marked as admin",
    },
    QueryTemplate {
        question: "Who can create users?",
        canonical: "who can do iam:CreateUser with *",
        description: "Principals allowed to call iam:CreateUser",
    },
    QueryTemplate {
        question: "Who can read S3?",
        canonical: "who can do s3:GetObject with *",
        description: "Principals allowed to read any S3 object",
    },
    QueryTemplate {
        question: "Who can delete S3 buckets?",
        canonical: "who can do s3:DeleteBucket with *",
        description: "Principals allowed to destroy S3 buckets",
    },
    QueryTemplate {
        question: "Who can escalate to admin?",
        canonical: "preset privesc",
        description: "Non-admin principals with known escalation paths",
    },
    QueryTemplate {
        question: "What services can assume X?",
        canonical: "preset serviceaccess",
        description: "Map of AWS services to roles they can assume",
    },
    QueryTemplate {
        question: "Who can assume a role?",
        canonical: "who can do sts:AssumeRole with *",
        description: "Principals allowed to call sts:AssumeRole",
    },
    QueryTemplate {
        question: "Who can invoke Lambda?",
        canonical: "who can invoke lambda:InvokeFunction on *",
        description: "Principals allowed to invoke any Lambda function",
    },
    QueryTemplate {
        question: "What can <principal> do?",
        canonical: "what can user/alice",
        description: "Enumerate a principal's reachable set",
    },
    QueryTemplate {
        question: "Compare two principals",
        canonical: "compare user/alice and user/bob",
        description: "Show permission set difference",
    },
    QueryTemplate {
        question: "Cypher-style graph pattern",
        canonical: "match (a)-[*]->(b:admin)",
        description: "Find principals with any path to an admin",
    },
];
