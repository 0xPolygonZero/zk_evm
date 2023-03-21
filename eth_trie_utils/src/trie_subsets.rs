use crate::{
    nibbles::Nibbles,
    partial_trie::{Node, TrieNode, WrappedNode},
};

#[derive(Debug)]
enum TrackedNodeIntern<N: TrieNode> {
    Empty(TrackedNodeInfo<N>),
    Hash(TrackedNodeInfo<N>),
    Branch(Box<[TrackedNode<N>; 16]>),
    Extension(Box<TrackedNode<N>>),
    Leaf(TrackedNodeInfo<N>),
}

#[derive(Debug)]
struct TrackedNode<N: TrieNode> {
    node: TrackedNodeIntern<N>,
    info: TrackedNodeInfo<N>,
}

impl<N: TrieNode> TrackedNode<N> {
    fn new(underlying_node: &Node<N>) -> Self {
        Self {
            node: match underlying_node {
                Node::Empty => {
                    TrackedNodeIntern::Empty(TrackedNodeInfo::new(underlying_node.clone()))
                }
                Node::Hash(_) => {
                    TrackedNodeIntern::Hash(TrackedNodeInfo::new(underlying_node.clone()))
                }
                Node::Branch { children, value: _ } => {
                    TrackedNodeIntern::Branch(Box::new(branch(children)))
                }

                Node::Extension {
                    nibbles: _,
                    child: _,
                } => TrackedNodeIntern::Extension(Box::new(TrackedNode::new(underlying_node))),
                Node::Leaf {
                    nibbles: _,
                    value: _,
                } => TrackedNodeIntern::Leaf(TrackedNodeInfo::new(underlying_node.clone())),
            },
            info: TrackedNodeInfo::new(underlying_node.clone()),
        }
    }
}

fn branch<N: TrieNode>(underlying_children: &[WrappedNode<N>; 16]) -> [TrackedNode<N>; 16] {
    [
        TrackedNode::new(&***underlying_children[0]),
        TrackedNode::new(&***underlying_children[1]),
        TrackedNode::new(&***underlying_children[2]),
        TrackedNode::new(&***underlying_children[3]),
        TrackedNode::new(&***underlying_children[4]),
        TrackedNode::new(&***underlying_children[5]),
        TrackedNode::new(&***underlying_children[6]),
        TrackedNode::new(&***underlying_children[7]),
        TrackedNode::new(&***underlying_children[8]),
        TrackedNode::new(&***underlying_children[9]),
        TrackedNode::new(&***underlying_children[10]),
        TrackedNode::new(&***underlying_children[11]),
        TrackedNode::new(&***underlying_children[12]),
        TrackedNode::new(&***underlying_children[13]),
        TrackedNode::new(&***underlying_children[14]),
        TrackedNode::new(&***underlying_children[15]),
    ]
}

#[derive(Debug)]
struct TrackedNodeInfo<N: TrieNode> {
    underlying_node: Node<N>,
    touched: bool,
}

impl<N: TrieNode> TrackedNodeInfo<N> {
    fn new(underlying_node: Node<N>) -> Self {
        Self {
            underlying_node,
            touched: false,
        }
    }

    fn reset(&mut self) {
        self.touched = false;
    }
}

pub(crate) fn create_trie_subset<N, K>(trie: &Node<N>, keys_involved: impl Iterator<Item = K>) -> N
where
    N: TrieNode,
    K: Into<Nibbles>,
{
    let mut tracked_trie = TrackedNode::new(trie);
    create_trie_subset_intern(&mut tracked_trie, keys_involved)
}

fn create_trie_subsets<N, K>(
    base_trie: &Node<N>,
    keys_involved: impl Iterator<Item = impl Iterator<Item = K>>,
) -> Vec<N>
where
    N: TrieNode,
    K: Into<Nibbles>,
{
    let mut tracked_trie = TrackedNode::new(base_trie);

    keys_involved
        .map(|ks| {
            let res = create_trie_subset_intern(&mut tracked_trie, ks);
            reset_tracked_trie_state(&mut tracked_trie);

            res
        })
        .collect()
}

fn create_trie_subset_intern<N, K>(
    tracked_trie: &mut TrackedNode<N>,
    keys_involved: impl Iterator<Item = K>,
) -> N
where
    N: TrieNode,
    K: Into<Nibbles>,
{
    for k in keys_involved {
        mark_nodes_that_are_needed(tracked_trie, k.into());
    }

    create_partial_trie_subset_from_tracked_trie(tracked_trie)
}

fn mark_nodes_that_are_needed<N: TrieNode>(_trie: &mut TrackedNode<N>, _k: Nibbles) {}

fn create_partial_trie_subset_from_tracked_trie<N: TrieNode>(_trie: &TrackedNode<N>) -> N {
    todo!()
}

fn reset_tracked_trie_state<N: TrieNode>(tracked_trie: &mut TrackedNode<N>) {
    match tracked_trie.node {
        TrackedNodeIntern::Branch(ref mut children) => {
            children.iter_mut().for_each(|c| c.info.reset())
        }
        TrackedNodeIntern::Extension(ref mut child) => child.info.reset(),
        TrackedNodeIntern::Empty(ref mut info)
        | TrackedNodeIntern::Hash(ref mut info)
        | TrackedNodeIntern::Leaf(ref mut info) => info.reset(),
    }
}
