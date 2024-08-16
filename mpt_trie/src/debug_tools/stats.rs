//! Simple tooling to extract stats from tries.
//!
//! This is particularly useful when comparing a "base" trie against a sub-trie
//! (hashed out trie) created from it.

use std::fmt::{self, Display};

use num_traits::ToPrimitive;

use crate::partial_trie::{Node, PartialTrie};

#[derive(Clone, Debug, Default)]
/// Statistics for a given trie, consisting of node count aggregated
/// by time, lowest depth and average depth of leaf and hash nodes.
pub struct TrieStats {
    name: Option<String>,
    counts: NodeCounts,
    depth_stats: DepthStats,
}

impl Display for TrieStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Trie Stats:")?;

        match self.name.as_ref() {
            Some(name) => writeln!(f, " ({})", name)?,
            None => writeln!(f)?,
        }

        writeln!(f, "Counts:\n{}", self.counts)?;
        writeln!(f, "Depth stats:\n{}", self.depth_stats)
    }
}

impl TrieStats {
    /// Compares with the statistics of another trie.
    pub const fn compare(&self, other: &Self) -> TrieComparison {
        TrieComparison {
            node_comp: self.counts.compare(&other.counts),
            depth_comp: self.depth_stats.compare(&other.depth_stats),
        }
    }
}

/// Total node counts for a trie.
#[derive(Clone, Debug, Default, Hash)]
struct NodeCounts {
    empty: usize,
    hash: usize,
    branch: usize,
    extension: usize,
    leaf: usize,
}

impl Display for NodeCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tot_nodes = self.total_nodes();

        Self::write_node_count_stats(f, "Empty", self.empty, tot_nodes)?;
        Self::write_node_count_stats(f, "Hash", self.hash, tot_nodes)?;
        Self::write_node_count_stats(f, "Branch", self.branch, tot_nodes)?;
        Self::write_node_count_stats(f, "Extension", self.extension, tot_nodes)?;
        Self::write_node_count_stats(f, "Leaf", self.leaf, tot_nodes)
    }
}

impl NodeCounts {
    fn write_node_count_stats(
        f: &mut fmt::Formatter<'_>,
        node_t_name: &str,
        count: usize,
        tot_count: usize,
    ) -> fmt::Result {
        let perc = (count as f32 / tot_count as f32) * 100.0;
        writeln!(f, "{}: {} ({:.2}%)", node_t_name, count, perc)
    }
}

impl NodeCounts {
    const fn total_nodes(&self) -> usize {
        self.empty + self.total_node_non_empty()
    }

    const fn total_node_non_empty(&self) -> usize {
        self.branch + self.extension + self.hash_and_leaf_node_count()
    }

    const fn hash_and_leaf_node_count(&self) -> usize {
        self.hash + self.leaf
    }

    const fn compare(&self, other: &Self) -> NodeComparison {
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

/// Information on the comparison between two tries.
#[derive(Clone, Debug)]
pub struct TrieComparison {
    node_comp: NodeComparison,
    depth_comp: DepthComparison,
}

impl Display for TrieComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Node comparison: {}", self.node_comp)?;
        writeln!(f, "Depth comparison: {}", self.depth_comp)
    }
}

// TODO: Consider computing these values lazily?
#[derive(Clone, Debug, Hash)]
struct NodeComparison {
    tot_node_rat: RatioStat<usize>,
    non_empty_rat: RatioStat<usize>,

    empty_rat: RatioStat<usize>,
    hash_rat: RatioStat<usize>,
    branch_rat: RatioStat<usize>,
    extension_rat: RatioStat<usize>,
    leaf_rat: RatioStat<usize>,
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

#[derive(Clone, Debug)]
struct DepthComparison {
    lowest_depth_rat: RatioStat<usize>,
    avg_leaf_depth_rat: RatioStat<f32>,
    avg_hash_depth_rat: RatioStat<f32>,
}

impl Display for DepthComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Lowest depth: {}", self.lowest_depth_rat)?;
        writeln!(f, "Avg leaf depth: {}", self.avg_leaf_depth_rat)?;
        writeln!(f, "Avg hash depth: {}", self.avg_hash_depth_rat)
    }
}

/// Type to hold (and compare) a given variable from two different tries.
#[derive(Clone, Debug, Hash)]
struct RatioStat<T> {
    a: T,
    b: T,
}

impl<T: Display + ToPrimitive> Display for RatioStat<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:.3} / {:.3} ({:.3}%)",
            self.a,
            self.b,
            // Note that the `Error` type for `fmt` does not hold any extra information and can
            // only indicate that something went wrong.
            self.get_a_over_b_perc().map_err(|_| fmt::Error)?
        )
    }
}

impl<T: ToPrimitive> RatioStat<T> {
    /// `new` doesn't have any logic, but this will reduce a lot of line lengths
    /// since this is called so many times.
    const fn new(a: T, b: T) -> Self {
        Self { a, b }
    }

    fn get_a_over_b_perc(&self) -> Result<f32, ()> {
        Ok((Self::try_to_f32(&self.a)? / Self::try_to_f32(&self.b)?) * 100.0)
    }

    fn try_to_f32(v: &T) -> Result<f32, ()> {
        v.to_f32().ok_or(())
    }
}

/// "Raw" state that is mutated as we traverse down the trie. Is processed into
/// a more useful format later on.
#[derive(Debug, Default)]
struct CurrTrackingState {
    counts: NodeCounts,

    // The "*_sum" variables are just accumulators that we process later to get average depths.
    leaf_depth_sum: u64,
    hash_depth_sum: u64,
    lowest_depth: usize,
}

impl CurrTrackingState {
    fn update_lowest_depth_if_larger(&mut self, curr_depth: usize) {
        if self.lowest_depth < curr_depth {
            self.lowest_depth = curr_depth;
        }
    }
}

/// Depth in terms of node depth (not key length).
#[derive(Clone, Debug, Default)]
struct DepthStats {
    lowest_depth: usize,
    avg_leaf_depth: f32,
    avg_hash_depth: f32,
}

impl Display for DepthStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Lowest depth: {}", self.lowest_depth)?;
        writeln!(f, "Average leaf depth: {:.3}", self.avg_leaf_depth)?;
        writeln!(f, "Average hash depth: {:.3}", self.avg_hash_depth)
    }
}

impl DepthStats {
    const fn compare(&self, other: &Self) -> DepthComparison {
        DepthComparison {
            lowest_depth_rat: RatioStat::new(self.lowest_depth, other.lowest_depth),
            avg_leaf_depth_rat: RatioStat::new(self.avg_leaf_depth, other.avg_leaf_depth),
            avg_hash_depth_rat: RatioStat::new(self.avg_hash_depth, other.avg_hash_depth),
        }
    }
}

/// Returns trie statistics consisting of node type counts as well as depth
/// statistics.
pub fn get_trie_stats<T: PartialTrie>(trie: &T) -> TrieStats {
    get_trie_stats_common(trie, None)
}

/// Returns trie statistics with a given name.
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
        trie_ops::TrieOpResult,
    };

    const MASSIVE_TRIE_SIZE: usize = 100_000;

    #[test]
    fn hand_made_trie_has_correct_node_stats() -> TrieOpResult<()> {
        let (trie, _) = handmade_trie_1()?;
        let stats = get_trie_stats(&trie);

        assert_eq!(stats.counts.leaf, 4);
        assert_eq!(stats.counts.hash, 0);
        assert_eq!(stats.counts.branch, 4);
        assert_eq!(stats.counts.extension, 2);

        // empty = (n_branch * 4) - n_leaf - (n_branch - 1)
        assert_eq!(stats.counts.empty, 57);

        Ok(())
    }

    // TODO: Low-priority. Finish later.
    #[test]
    #[ignore]
    fn perfectly_balanced_trie_has_correct_node_stats() {
        todo!()
    }

    #[test]
    fn massive_leaf_trie_has_correct_leaf_node_stats() -> TrieOpResult<()> {
        create_trie_and_stats_from_entries_and_assert(MASSIVE_TRIE_SIZE, 0, 9522)
    }

    #[test]
    fn massive_hash_trie_has_correct_hash_node_stats() -> TrieOpResult<()> {
        create_trie_and_stats_from_entries_and_assert(0, MASSIVE_TRIE_SIZE, 9855)
    }

    #[test]
    fn massive_mixed_trie_has_correct_hash_node_stats() -> TrieOpResult<()> {
        create_trie_and_stats_from_entries_and_assert(
            MASSIVE_TRIE_SIZE / 2,
            MASSIVE_TRIE_SIZE / 2,
            1992,
        )
    }

    fn create_trie_and_stats_from_entries_and_assert(
        n_leaf_nodes: usize,
        n_hash_nodes: usize,
        seed: u64,
    ) -> TrieOpResult<()> {
        let val_entries = generate_n_random_fixed_trie_value_entries(n_leaf_nodes, seed);
        let hash_entries = generate_n_random_fixed_trie_hash_entries(n_hash_nodes, seed + 1);

        let mut trie = HashedPartialTrie::default();
        trie.extend(val_entries)?;
        trie.extend(hash_entries)?;

        let stats = get_trie_stats(&trie);

        assert_eq!(stats.counts.leaf, n_leaf_nodes);
        assert_eq!(stats.counts.hash, n_hash_nodes);

        Ok(())
    }

    // TODO: Low-priority. Finish later.
    #[test]
    #[ignore]
    fn depth_stats_work() {
        todo!()
    }
}
