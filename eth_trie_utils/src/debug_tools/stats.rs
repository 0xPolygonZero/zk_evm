use std::fmt::{self, Display};

use crate::partial_trie::{Node, PartialTrie};

#[derive(Debug, Default)]
pub struct TrieStats {
    pub name: Option<String>,
    pub counts: NodeCounts,
    pub depth_stats: DepthStats,
}

impl Display for TrieStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Trie Stats:")?;

        match self.name.as_ref() {
            Some(name) => writeln!(f, " ({})", name)?,
            None => writeln!(f)?,
        }

        writeln!(f, "Counts: {}", self.counts)?;
        writeln!(f, "Depth stats: {}", self.depth_stats)
    }
}

impl TrieStats {
    pub fn compare(&self, other: &Self) -> TrieComparison {
        TrieComparison {
            node_comp: self.counts.compare(&other.counts),
            depth_comp: self.depth_stats.compare(&other.depth_stats),
        }
    }
}

#[derive(Debug, Default)]
pub struct NodeCounts {
    empty: usize,
    hash: usize,
    branch: usize,
    extension: usize,
    leaf: usize,
}

impl Display for NodeCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Empty: {}", self.empty)?;
        writeln!(f, "Hash: {}", self.hash)?;
        writeln!(f, "Branch: {}", self.branch)?;
        writeln!(f, "Extension: {}", self.extension)?;
        writeln!(f, "Leaf: {}", self.leaf)
    }
}

impl NodeCounts {
    pub fn total_nodes(&self) -> usize {
        self.empty + self.total_node_non_empty()
    }

    pub fn total_node_non_empty(&self) -> usize {
        self.branch + self.extension + self.hash_and_leaf_node_count()
    }

    pub fn hash_and_leaf_node_count(&self) -> usize {
        self.hash + self.leaf
    }

    pub fn compare(&self, other: &Self) -> NodeComparison {
        NodeComparison {
            tot_node_rat: RatioStat::new(self.total_nodes(), other.total_nodes()),
            non_empty_rat: RatioStat::new(
                self.total_node_non_empty(),
                other.total_node_non_empty(),
            ),
            empty_rat: RatioStat::new(self.empty, other.empty),
            hash_rat: RatioStat::new(self.hash, other.hash),
            branch_rat: RatioStat::new(self.branch, other.branch),
            extension_rat: RatioStat::new(self.extension, other.extension),
            leaf_rat: RatioStat::new(self.leaf, other.leaf),
        }
    }
}

#[derive(Debug)]
pub struct TrieComparison {
    node_comp: NodeComparison,
    depth_comp: DepthComparison,
}

impl Display for TrieComparison {
    // Pretty debug is pretty good by default If we want something better, we can do
    // our own.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Node comparison: {}", self.node_comp)?;
        writeln!(f, "Depth comparison: {}", self.depth_comp)
    }
}

// TODO: Consider computing these values lazily?
#[derive(Debug)]
pub struct NodeComparison {
    pub tot_node_rat: RatioStat,
    pub non_empty_rat: RatioStat,

    pub empty_rat: RatioStat,
    pub hash_rat: RatioStat,
    pub branch_rat: RatioStat,
    pub extension_rat: RatioStat,
    pub leaf_rat: RatioStat,
}

impl Display for NodeComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Total nodes: {}", self.tot_node_rat)?;
        writeln!(f, "Non-empty: {}", self.non_empty_rat)?;

        writeln!(f, "Total empty: {}", self.empty_rat)?;
        writeln!(f, "Total hash: {}", self.hash_rat)?;
        writeln!(f, "Total branch: {}", self.branch_rat)?;
        writeln!(f, "Total extension: {}", self.extension_rat)?;
        writeln!(f, "Total leaf: {}", self.leaf_rat)
    }
}

#[derive(Debug)]
struct DepthComparison {
    a: DepthStats,
    b: DepthStats,
}

impl Display for DepthComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Self::write_depth_stats_and_header(f, &self.a, "a")?;
        Self::write_depth_stats_and_header(f, &self.b, "b")
    }
}

impl DepthComparison {
    fn write_depth_stats_and_header(
        f: &mut fmt::Formatter<'_>,
        stats: &DepthStats,
        trie_str: &str,
    ) -> fmt::Result {
        writeln!(f, "Depth stats for {}:", trie_str)?;
        stats.fmt(f)
    }
}

#[derive(Debug)]
pub struct RatioStat {
    pub a: usize,
    pub b: usize,
}

impl Display for RatioStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} / {} ({}%)", self.a, self.b, self.get_a_over_b_perc())
    }
}

impl RatioStat {
    /// `new` doesn't do any logic, but this will reduce the line since since
    /// this is called so many times.
    fn new(a: usize, b: usize) -> Self {
        Self { a, b }
    }

    fn get_a_over_b_perc(&self) -> f32 {
        (self.a as f32 / self.b as f32) * 100.0
    }
}

#[derive(Debug, Default)]
struct CurrTrackingState {
    counts: NodeCounts,
    leaf_depth_sum: u64,
    hash_depth_sum: u64,
    lowest_depth: usize,
}

impl CurrTrackingState {
    fn update_lowest_depth_if_larger(&mut self, curr_depth: usize) {
        if self.lowest_depth > curr_depth {
            self.lowest_depth = curr_depth;
        }
    }
}

/// Depth in terms of node depth (not key length).
#[derive(Clone, Debug, Default)]
pub struct DepthStats {
    pub lowest_depth: usize,
    pub avg_leaf_depth: f32,
    pub avg_hash_depth: f32,
}

impl Display for DepthStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Lowest depth: {}", self.lowest_depth)?;
        writeln!(f, "Average leaf depth: {}", self.avg_leaf_depth)?;
        writeln!(f, "Average hash depth: {}", self.avg_hash_depth)
    }
}

impl DepthStats {
    fn compare(&self, other: &Self) -> DepthComparison {
        DepthComparison {
            a: self.clone(),
            b: other.clone(),
        }
    }
}

pub fn get_trie_stats<T: PartialTrie>(trie: &T) -> TrieStats {
    get_trie_stats_common(trie, None)
}

pub fn get_trie_stats_with_name<T: PartialTrie>(trie: &T, name: String) -> TrieStats {
    get_trie_stats_common(trie, Some(name))
}

fn get_trie_stats_common<T: PartialTrie>(trie: &T, name: Option<String>) -> TrieStats {
    let mut state = CurrTrackingState::default();

    get_trie_stats_rec(trie, &mut state, 0);

    let depth_stats = DepthStats {
        lowest_depth: state.lowest_depth,
        avg_leaf_depth: state.leaf_depth_sum as f32 / state.counts.leaf as f32,
        avg_hash_depth: state.hash_depth_sum as f32 / state.counts.hash as f32,
    };

    TrieStats {
        name,
        counts: state.counts,
        depth_stats,
    }
}

fn get_trie_stats_rec<T: PartialTrie>(
    node: &Node<T>,
    state: &mut CurrTrackingState,
    curr_depth: usize,
) {
    match node {
        Node::Empty => {
            state.counts.empty += 1;
        }
        Node::Hash(_) => {
            state.counts.hash += 1;
            state.hash_depth_sum += curr_depth as u64;
            state.update_lowest_depth_if_larger(curr_depth);
        }
        Node::Branch { children, value: _ } => {
            state.counts.branch += 1;

            for c in children {
                get_trie_stats_rec(c, state, curr_depth + 1);
            }
        }
        Node::Extension { nibbles: _, child } => {
            state.counts.extension += 1;
            get_trie_stats_rec(child, state, curr_depth + 1);
        }
        Node::Leaf {
            nibbles: _,
            value: _,
        } => {
            state.counts.leaf += 1;
            state.leaf_depth_sum += curr_depth as u64;
            state.update_lowest_depth_if_larger(curr_depth);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::get_trie_stats;
    use crate::{
        partial_trie::{HashedPartialTrie, PartialTrie},
        testing_utils::{
            generate_n_random_fixed_trie_hash_entries, generate_n_random_fixed_trie_value_entries,
            handmade_trie_1,
        },
    };

    const MASSIVE_TRIE_SIZE: usize = 100_000;

    #[test]
    fn hand_made_trie_has_correct_node_stats() {
        let (trie, _) = handmade_trie_1();
        let stats = get_trie_stats(&trie);

        assert_eq!(stats.counts.leaf, 4);
        assert_eq!(stats.counts.hash, 0);
        assert_eq!(stats.counts.branch, 4);
        assert_eq!(stats.counts.extension, 2);
        assert_eq!(stats.counts.empty, 57); // (n_branch * 4) - n_leaf -
                                            // (n_branch - 1)
    }

    // TODO: Low-priority. Finish later.
    #[test]
    #[ignore]
    fn perfectly_balanced_trie_has_correct_node_stats() {
        todo!()
    }

    #[test]
    fn massive_leaf_trie_has_correct_leaf_node_stats() {
        let entries = generate_n_random_fixed_trie_value_entries(MASSIVE_TRIE_SIZE, 9522);
        let trie = HashedPartialTrie::from_iter(entries);

        let stats = get_trie_stats(&trie);

        assert_eq!(stats.counts.leaf, MASSIVE_TRIE_SIZE);
        assert_eq!(stats.counts.hash, 0);
    }

    #[test]
    fn massive_hash_trie_has_correct_hash_node_stats() {
        let entries = generate_n_random_fixed_trie_hash_entries(MASSIVE_TRIE_SIZE, 9855);
        let trie = HashedPartialTrie::from_iter(entries);

        let stats = get_trie_stats(&trie);

        assert_eq!(stats.counts.hash, MASSIVE_TRIE_SIZE);
        assert_eq!(stats.counts.leaf, 0);
    }

    #[test]
    fn massive_mixed_trie_has_correct_hash_node_stats() {
        let val_entries = generate_n_random_fixed_trie_value_entries(MASSIVE_TRIE_SIZE / 2, 1992);
        let hash_entries = generate_n_random_fixed_trie_hash_entries(MASSIVE_TRIE_SIZE / 2, 404);

        let mut trie = HashedPartialTrie::default();
        trie.extend(val_entries);
        trie.extend(hash_entries);

        let stats = get_trie_stats(&trie);

        assert_eq!(stats.counts.leaf, MASSIVE_TRIE_SIZE / 2);
        assert_eq!(stats.counts.hash, MASSIVE_TRIE_SIZE / 2);
    }

    // TODO: Low-priority. Finish later.
    #[test]
    #[ignore]
    fn depth_stats_work() {
        todo!()
    }
}
