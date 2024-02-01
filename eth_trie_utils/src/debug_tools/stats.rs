use crate::partial_trie::{Node, PartialTrie};

#[derive(Debug, Default)]
pub struct TrieStats {
    pub counts: NodeCounts,
    pub depth_stats: DepthStats,
}

#[derive(Debug, Default)]
pub struct NodeCounts {
    empty: usize,
    hash: usize,
    branch: usize,
    extension: usize,
    leaf: usize,
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

    pub fn compare(&self, _other: &Self) -> TrieComparison {
        todo!()
    }
}

#[derive(Debug, Default)]
pub struct TrieComparison {}

#[derive(Debug, Default)]
struct CurrTrackingState {
    counts: NodeCounts,
    leaf_and_hash_depth_sum: u64,
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
#[derive(Debug, Default)]
pub struct DepthStats {
    pub lowest_depth: usize,
    pub avg_leaf_depth: f32,
}

pub fn get_trie_stats<T: PartialTrie>(trie: &T) -> TrieStats {
    let mut state = CurrTrackingState::default();

    get_trie_stats_rec(trie, &mut state, 0);

    let depth_stats = DepthStats {
        lowest_depth: state.lowest_depth,
        avg_leaf_depth: state.leaf_and_hash_depth_sum as f32
            / state.counts.hash_and_leaf_node_count() as f32,
    };

    TrieStats {
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
            state.leaf_and_hash_depth_sum += curr_depth as u64;
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
            state.leaf_and_hash_depth_sum += curr_depth as u64;
            state.update_lowest_depth_if_larger(curr_depth);
        }
    }
}
