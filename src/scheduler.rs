use std::sync::Arc;
use std::time::Duration;
use std::sync::atomic::Ordering;
use std::collections::HashMap;

use crate::config::{GroupConfig, GroupStrategy};
use crate::backend::{BackendEntry, BackendInfo};

#[derive(Debug, Clone)]
pub enum GroupMember {
    Backend(usize),
    Group(usize),
}

#[derive(Debug, Clone)]
pub struct Group {
    pub name: String,
    pub strategy: GroupStrategy,
    pub members: Vec<GroupMember>,
}

impl Group {
    /// Recursively flatten this group into an ordered list of backend indices,
    /// applying each nested group's strategy along the way.
    pub fn flatten_backend_indices(&self, all_groups: &[Group]) -> Vec<usize> {
        let mut result = Vec::new();
        for member in &self.members {
            match member {
                GroupMember::Backend(idx) => result.push(*idx),
                GroupMember::Group(g_idx) => {
                    if let Some(nested) = all_groups.get(*g_idx) {
                        result.extend(nested.flatten_backend_indices(all_groups));
                    }
                }
            }
        }
        result
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Backend(usize),
    Group(usize),
}

pub fn build_hash_ring(healthy: &[(usize, Arc<BackendInfo>)]) -> Vec<(u64, usize)> {
    let mut ring = Vec::new();
    for (i, (_, info)) in healthy.iter().enumerate() {
        for v in 0..160 {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(&info.name, &mut hasher);
            std::hash::Hash::hash(&v, &mut hasher);
            ring.push((std::hash::Hasher::finish(&hasher), i));
        }
    }
    ring.sort_unstable_by_key(|(h, _)| *h);
    ring
}

pub struct CachedCandidates {
    pub strategy: crate::config::GroupStrategy,
    pub hash_ring: Vec<(u64, usize)>,
    pub healthy: Vec<(usize, Arc<BackendInfo>)>,
    pub unhealthy: Vec<(usize, Arc<BackendInfo>)>,
}

pub fn build_groups_and_failover_order(
    entries: &[BackendEntry],
    group_configs: &[GroupConfig],
    failover_order_cfg: Option<&Vec<String>>,
) -> (Vec<Group>, Vec<Target>) {
    // First pass: create groups with name-only references so we can build an
    // index map. We resolve the actual GroupMember variants in a second pass.
    let group_name_to_idx: HashMap<&str, usize> = group_configs
        .iter()
        .enumerate()
        .map(|(i, gc)| (gc.name.as_str(), i))
        .collect();

    let mut groups = Vec::with_capacity(group_configs.len());
    for gc in group_configs {
        let mut members = Vec::new();
        for member_name in &gc.members {
            if let Some(&g_idx) = group_name_to_idx.get(member_name.as_str()) {
                members.push(GroupMember::Group(g_idx));
            } else if let Some(pos) = entries.iter().position(|e| e.info.name == *member_name) {
                members.push(GroupMember::Backend(pos));
            }
        }
        groups.push(Group {
            name: gc.name.clone(),
            strategy: gc.strategy,
            members,
        });
    }

    let mut failover_order = Vec::new();
    if let Some(order) = failover_order_cfg {
        for target_name in order {
            if let Some(&pos) = group_name_to_idx.get(target_name.as_str()) {
                failover_order.push(Target::Group(pos));
            } else if let Some(pos) = entries.iter().position(|e| e.info.name == *target_name) {
                failover_order.push(Target::Backend(pos));
            }
        }
    } else {
        // Default failover order:
        // 1. Groups with strategy Failover
        for (i, g) in groups.iter().enumerate() {
            if g.strategy == GroupStrategy::Failover {
                failover_order.push(Target::Group(i));
            }
        }

        // 2. Groups with strategy UrlTest or LoadBalance
        for (i, g) in groups.iter().enumerate() {
            if g.strategy == GroupStrategy::UrlTest || g.strategy == GroupStrategy::LoadBalance {
                failover_order.push(Target::Group(i));
            }
        }

        // 3. Standalone backends (not in any group)
        let mut grouped_indices = std::collections::HashSet::new();
        for g in &groups {
            for idx in g.flatten_backend_indices(&groups) {
                grouped_indices.insert(idx);
            }
        }

        for i in 0..entries.len() {
            if !grouped_indices.contains(&i) {
                failover_order.push(Target::Backend(i));
            }
        }
    }

    (groups, failover_order)
}

/// Recursively collect backend candidates from a group, returning ordered blocks of indices.
pub fn collect_group_candidates_recursive(
    group: &Group,
    entries: &[BackendEntry],
    groups: &[Group],
) -> (Vec<usize>, Vec<usize>) {
    let mut member_results = Vec::new();

    for member in &group.members {
        let (h, u) = match member {
            GroupMember::Backend(idx) => {
                if let Some(entry) = entries.get(*idx) {
                    let status = entry.status.lock();
                    if status.enabled {
                        if status.healthy {
                            (vec![*idx], vec![])
                        } else {
                            (vec![], vec![*idx])
                        }
                    } else {
                        (vec![], vec![])
                    }
                } else {
                    (vec![], vec![])
                }
            }
            GroupMember::Group(g_idx) => {
                if let Some(nested) = groups.get(*g_idx) {
                    collect_group_candidates_recursive(nested, entries, groups)
                } else {
                    (vec![], vec![])
                }
            }
        };
        member_results.push((h, u));
    }

    let mut sorted_healthy: Vec<_> = member_results.iter().map(|(h, _)| h.clone()).collect();
    apply_strategy_sort_nested(&group.strategy, entries, &mut sorted_healthy);

    let mut sorted_unhealthy: Vec<_> = member_results.iter().map(|(_, u)| u.clone()).collect();
    apply_strategy_sort_nested(&group.strategy, entries, &mut sorted_unhealthy);

    let flat_h = sorted_healthy.into_iter().flatten().collect();
    let flat_u = sorted_unhealthy.into_iter().flatten().collect();

    (flat_h, flat_u)
}

pub fn apply_strategy_sort_nested(
    strategy: &GroupStrategy,
    entries: &[BackendEntry],
    blocks: &mut Vec<Vec<usize>>,
) {
    match strategy {
        GroupStrategy::UrlTest => {
            blocks.sort_by_key(|block| {
                block
                    .first()
                    .and_then(|&idx| entries.get(idx).and_then(|e| e.status.lock().last_latency))
                    .unwrap_or(Duration::MAX)
            });
        }
        GroupStrategy::Failover | GroupStrategy::ConsistentHashing => {
            // Keep configured order
        }
        GroupStrategy::LoadBalance => {
            blocks.sort_by_key(|block| {
                if let Some(&idx) = block.first() {
                    if let Some(entry) = entries.get(idx) {
                        let tc = &entry.traffic;
                        return (
                            tc.total_connections.load(Ordering::Relaxed),
                            tc.active_connections.load(Ordering::Relaxed),
                        );
                    }
                }
                (u64::MAX, i64::MAX)
            });
        }
    }
}

pub fn deduplicate_candidates(
    raw_h: Vec<usize>,
    raw_u: Vec<usize>,
    entries: &[BackendEntry],
) -> (Vec<(usize, Arc<BackendInfo>)>, Vec<(usize, Arc<BackendInfo>)>) {
    let mut h = Vec::new();
    let mut u = Vec::new();
    let mut added_h = std::collections::HashSet::new();
    let mut added_u = std::collections::HashSet::new();

    for idx in raw_h {
        if added_h.insert(idx) {
            if let Some(entry) = entries.get(idx) {
                h.push((idx, Arc::clone(&entry.info)));
            }
        }
    }
    for idx in raw_u {
        if !added_h.contains(&idx) && added_u.insert(idx) {
            if let Some(entry) = entries.get(idx) {
                u.push((idx, Arc::clone(&entry.info)));
            }
        }
    }
    (h, u)
}

pub fn calculate_candidates(
    entries: &[BackendEntry],
    groups: &[Group],
    failover_order: &[Target],
) -> (Vec<(usize, Arc<BackendInfo>)>, Vec<(usize, Arc<BackendInfo>)>) {
    let mut raw_h = Vec::new();
    let mut raw_u = Vec::new();

    for target in failover_order {
        match target {
            Target::Backend(idx) => {
                if let Some(entry) = entries.get(*idx) {
                    let status = entry.status.lock();
                    if status.enabled {
                        if status.healthy {
                            raw_h.push(*idx);
                        } else {
                            raw_u.push(*idx);
                        }
                    }
                }
            }
            Target::Group(g_idx) => {
                if let Some(group) = groups.get(*g_idx) {
                    let (gh, gu) = collect_group_candidates_recursive(group, entries, groups);
                    raw_h.extend(gh);
                    raw_u.extend(gu);
                }
            }
        }
    }

    deduplicate_candidates(raw_h, raw_u, entries)
}

/// Calculate candidates for a specific route target (group or backend name).
pub fn calculate_route_candidates(
    route: &str,
    entries: &[BackendEntry],
    groups: &[Group],
) -> (crate::config::GroupStrategy, Vec<(usize, Arc<BackendInfo>)>, Vec<(usize, Arc<BackendInfo>)>) {
    if let Some(group) = groups.iter().find(|g| g.name == route) {
        let (raw_h, raw_u) = collect_group_candidates_recursive(group, entries, groups);
        let (h, u) = deduplicate_candidates(raw_h, raw_u, entries);
        return (group.strategy, h, u);
    }

    if let Some(idx) = entries.iter().position(|e| e.info.name == route) {
        if let Some(entry) = entries.get(idx) {
            let status = entry.status.lock();
            if status.enabled {
                if status.healthy {
                    return (crate::config::GroupStrategy::Failover, vec![(idx, Arc::clone(&entry.info))], vec![]);
                } else {
                    return (crate::config::GroupStrategy::Failover, vec![], vec![(idx, Arc::clone(&entry.info))]);
                }
            }
        }
    }

    (crate::config::GroupStrategy::Failover, vec![], vec![])
}
