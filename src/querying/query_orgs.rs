use crate::model::org_tree::OrganizationTree;
use crate::model::policy::Policy;

/// Produce a list of SCP groups applicable to a given account within the organization.
/// Each group is a list of Policy objects at one level of the org hierarchy.
pub fn produce_scp_list<'a>(org_tree: &'a OrganizationTree, account_id: &str) -> Vec<Vec<Policy>> {
    let scp_groups = org_tree.get_scps_for_account(account_id);
    scp_groups
        .into_iter()
        .map(|group| {
            group
                .into_iter()
                .map(|scp| Policy::new(&scp.arn, &scp.name, scp.policy_doc.clone()))
                .collect()
        })
        .collect()
}
