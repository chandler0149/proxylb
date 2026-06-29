use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::backend::{BackendEntry, BackendInfo};
use crate::config::{GroupConfig, GroupStrategy};

#[derive(Debug, Clone)]
pub enum GroupMember {
    Backend(usize, u32),
    Group(usize, u32),
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
                GroupMember::Backend(idx, _) => result.push(*idx),
                GroupMember::Group(g_idx, _) => {
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

pub fn build_hash_ring(healthy: &[(usize, u32, Arc<BackendInfo>)]) -> Vec<(u64, usize)> {
    let mut ring = Vec::new();
    for (i, (_, _, info)) in healthy.iter().enumerate() {
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

pub struct SubGroupCache {
    pub strategy: crate::config::GroupStrategy,
    pub hash_ring: Vec<(u64, usize)>,
    pub wrr_choices: Vec<usize>,
    pub healthy: Vec<(usize, u32, Arc<BackendInfo>)>,
}

pub struct CachedCandidates {
    pub subgroups: Vec<SubGroupCache>,
    pub unhealthy: Vec<(usize, u32, Arc<BackendInfo>)>,
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
        for member_cfg in &gc.members {
            let member_name = member_cfg.name();
            let member_weight = member_cfg.weight();
            if let Some(&g_idx) = group_name_to_idx.get(member_name) {
                members.push(GroupMember::Group(g_idx, member_weight));
            } else if let Some(pos) = entries.iter().position(|e| e.info.name == member_name) {
                members.push(GroupMember::Backend(pos, member_weight));
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

        // 2. Groups with other strategies (UrlTest, LoadBalance, ConsistentHashing, WeightedRoundRobin)
        for (i, g) in groups.iter().enumerate() {
            if g.strategy != GroupStrategy::Failover {
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

pub struct RawSubGroup {
    pub strategy: GroupStrategy,
    pub members: Vec<(usize, u32)>,
}

/// Recursively collect backend candidates from a group, returning ordered blocks of indices.
pub fn collect_group_candidates_recursive(
    group: &Group,
    entries: &[BackendEntry],
    groups: &[Group],
    parent_weight: u32,
) -> (Vec<RawSubGroup>, Vec<(usize, u32)>) {
    let mut healthy_subgroups = Vec::new();
    let mut unhealthy = Vec::new();

    for member in &group.members {
        match member {
            GroupMember::Backend(idx, weight) => {
                let effective_weight = weight * parent_weight;
                if let Some(entry) = entries.get(*idx) {
                    let status = entry.status.lock();
                    if status.enabled {
                        if status.healthy {
                            healthy_subgroups.push(RawSubGroup {
                                strategy: GroupStrategy::Failover,
                                members: vec![(*idx, effective_weight)],
                            });
                        } else {
                            unhealthy.push((*idx, effective_weight));
                        }
                    }
                }
            }
            GroupMember::Group(g_idx, weight) => {
                let effective_weight = weight * parent_weight;
                if let Some(nested) = groups.get(*g_idx) {
                    let (mut gh, mut gu) = collect_group_candidates_recursive(
                        nested,
                        entries,
                        groups,
                        effective_weight,
                    );
                    healthy_subgroups.append(&mut gh);
                    unhealthy.append(&mut gu);
                }
            }
        }
    }

    match group.strategy {
        GroupStrategy::Failover => (healthy_subgroups, unhealthy),
        GroupStrategy::UrlTest => {
            let mut flat: Vec<(usize, u32)> = healthy_subgroups
                .into_iter()
                .flat_map(|sg| sg.members)
                .collect();
            flat.sort_by_key(|&(idx, _)| {
                entries
                    .get(idx)
                    .and_then(|e| e.status.lock().last_latency)
                    .unwrap_or(Duration::MAX)
            });
            (
                vec![RawSubGroup {
                    strategy: GroupStrategy::Failover,
                    members: flat,
                }],
                unhealthy,
            )
        }
        GroupStrategy::LoadBalance => {
            let mut flat: Vec<(usize, u32)> = healthy_subgroups
                .into_iter()
                .flat_map(|sg| sg.members)
                .collect();
            flat.sort_by_key(|&(idx, _)| {
                if let Some(entry) = entries.get(idx) {
                    let tc = &entry.traffic;
                    (
                        tc.total_connections.load(Ordering::Relaxed),
                        tc.active_connections.load(Ordering::Relaxed),
                    )
                } else {
                    (u64::MAX, i64::MAX)
                }
            });
            (
                vec![RawSubGroup {
                    strategy: GroupStrategy::Failover,
                    members: flat,
                }],
                unhealthy,
            )
        }
        GroupStrategy::WeightedRoundRobin | GroupStrategy::ConsistentHashing => {
            let flat: Vec<(usize, u32)> = healthy_subgroups
                .into_iter()
                .flat_map(|sg| sg.members)
                .collect();
            (
                vec![RawSubGroup {
                    strategy: group.strategy,
                    members: flat,
                }],
                unhealthy,
            )
        }
    }
}

pub fn deduplicate_subgroups(
    raw_h: Vec<RawSubGroup>,
    raw_u: Vec<(usize, u32)>,
    entries: &[BackendEntry],
) -> (Vec<SubGroupCache>, Vec<(usize, u32, Arc<BackendInfo>)>) {
    let mut added_h = std::collections::HashSet::new();
    let mut added_u = std::collections::HashSet::new();

    let mut subgroups = Vec::new();
    for sg in raw_h {
        let mut h = Vec::new();
        for (idx, weight) in sg.members {
            if added_h.insert(idx) {
                if let Some(entry) = entries.get(idx) {
                    h.push((idx, weight, Arc::clone(&entry.info)));
                }
            }
        }
        if !h.is_empty() {
            let wrr_choices = if sg.strategy == GroupStrategy::WeightedRoundRobin {
                build_wrr_choices(&h, entries)
            } else {
                Vec::new()
            };
            let hash_ring = if sg.strategy == GroupStrategy::ConsistentHashing {
                build_hash_ring(&h)
            } else {
                Vec::new()
            };
            subgroups.push(SubGroupCache {
                strategy: sg.strategy,
                wrr_choices,
                hash_ring,
                healthy: h,
            });
        }
    }

    let mut u = Vec::new();
    for (idx, weight) in raw_u {
        if !added_h.contains(&idx) && added_u.insert(idx) {
            if let Some(entry) = entries.get(idx) {
                u.push((idx, weight, Arc::clone(&entry.info)));
            }
        }
    }

    (subgroups, u)
}

pub fn calculate_candidates(
    entries: &[BackendEntry],
    groups: &[Group],
    failover_order: &[Target],
) -> (Vec<SubGroupCache>, Vec<(usize, u32, Arc<BackendInfo>)>) {
    let mut raw_h = Vec::new();
    let mut raw_u = Vec::new();

    for target in failover_order {
        match target {
            Target::Backend(idx) => {
                if let Some(entry) = entries.get(*idx) {
                    let status = entry.status.lock();
                    if status.enabled {
                        if status.healthy {
                            raw_h.push(RawSubGroup {
                                strategy: GroupStrategy::Failover,
                                members: vec![(*idx, 1)],
                            });
                        } else {
                            raw_u.push((*idx, 1));
                        }
                    }
                }
            }
            Target::Group(g_idx) => {
                if let Some(group) = groups.get(*g_idx) {
                    let (gh, gu) = collect_group_candidates_recursive(group, entries, groups, 1);
                    raw_h.extend(gh);
                    raw_u.extend(gu);
                }
            }
        }
    }

    deduplicate_subgroups(raw_h, raw_u, entries)
}

/// Calculate candidates for a specific route target (group or backend name).
pub fn calculate_route_candidates(
    route: &str,
    entries: &[BackendEntry],
    groups: &[Group],
) -> (Vec<SubGroupCache>, Vec<(usize, u32, Arc<BackendInfo>)>) {
    if let Some(group) = groups.iter().find(|g| g.name == route) {
        let (raw_h, raw_u) = collect_group_candidates_recursive(group, entries, groups, 1);
        let (h, u) = deduplicate_subgroups(raw_h, raw_u, entries);
        return (h, u);
    }

    if let Some(idx) = entries.iter().position(|e| e.info.name == route) {
        if let Some(entry) = entries.get(idx) {
            let status = entry.status.lock();
            if status.enabled {
                if status.healthy {
                    let (h, u) = deduplicate_subgroups(
                        vec![RawSubGroup {
                            strategy: GroupStrategy::Failover,
                            members: vec![(idx, 1)],
                        }],
                        vec![],
                        entries,
                    );
                    return (h, u);
                } else {
                    let (h, u) = deduplicate_subgroups(vec![], vec![(idx, 1)], entries);
                    return (h, u);
                }
            }
        }
    }

    (vec![], vec![])
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// Build the WRR selection table.
///
/// Returns an array of **positions in the `healthy` slice** (not backend pool
/// indices). This lets the hot-path rotate the healthy array in O(1) without
/// a linear search.  Weights are GCD-reduced so the table is as small as
/// possible (e.g. weights 300:600 → 1:2 → 3 entries instead of 900).
pub fn build_wrr_choices(
    healthy: &[(usize, u32, Arc<BackendInfo>)],
    _entries: &[BackendEntry],
) -> Vec<usize> {
    if healthy.is_empty() {
        return vec![];
    }

    // Collect raw weights and GCD-reduce.
    let mut raw: Vec<i64> = healthy.iter().map(|(_, w, _)| *w as i64).collect();
    let g = raw.iter().fold(0u64, |acc, &w| gcd(acc, w as u64));
    if g > 1 {
        for w in &mut raw {
            *w /= g as i64;
        }
    }

    let total: i64 = raw.iter().sum();

    if total == 0 {
        // All weights zero — simple round-robin over positions.
        return (0..healthy.len()).collect();
    }

    // Nginx smooth WRR — store healthy-array *positions*, not backend indices.
    let n = total as usize;
    let mut cw = vec![0i64; raw.len()];
    let mut choices = Vec::with_capacity(n);

    for _ in 0..n {
        let mut best = 0;
        let mut max = i64::MIN;
        for i in 0..raw.len() {
            cw[i] += raw[i];
            if cw[i] > max {
                max = cw[i];
                best = i;
            }
        }
        choices.push(best); // position in healthy[], not backend pool index
        cw[best] -= total;
    }

    choices
}
