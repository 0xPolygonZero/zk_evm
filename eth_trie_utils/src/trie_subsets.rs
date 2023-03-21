use std::sync::Arc;

use ethereum_types::H256;
use thiserror::Error;

use crate::{
    nibbles::Nibbles,
    partial_trie::{Node, TrieNode, WrappedNode},
    utils::TrieNodeType,
};

pub type SubsetTrieResult<T> = Result<T, SubsetTrieError>;

#[derive(Debug, Error)]
pub enum SubsetTrieError {
    #[error("Tried to mark nodes in a tracked trie for a key that does not exist! (Key: {0}, trie: {1})")]
    UnexpectedKey(Nibbles, String),
}

#[derive(Debug)]
enum TrackedNodeIntern<N: TrieNode> {
    Empty,
    Hash,
    Branch(Box<[TrackedNode<N>; 16]>),
    Extension(Box<TrackedNode<N>>),
    Leaf,
}

#[derive(Debug)]
struct TrackedNode<N: TrieNode> {
    node: TrackedNodeIntern<N>,
    info: TrackedNodeInfo<N>,
}

impl<N: Clone + TrieNode> TrackedNode<N> {
    fn new(underlying_node: &N) -> Self {
        Self {
            node: match &**underlying_node {
                Node::Empty => TrackedNodeIntern::Empty,
                Node::Hash(_) => TrackedNodeIntern::Hash,
                Node::Branch {
                    ref children,
                    value: _,
                } => TrackedNodeIntern::Branch(Box::new(tracked_branch(children))),
                Node::Extension {
                    nibbles: _,
                    child: _,
                } => TrackedNodeIntern::Extension(Box::new(TrackedNode::new(underlying_node))),
                Node::Leaf {
                    nibbles: _,
                    value: _,
                } => TrackedNodeIntern::Leaf,
            },
            info: TrackedNodeInfo::new(underlying_node.clone()),
        }
    }
}

fn tracked_branch<N: TrieNode>(underlying_children: &[WrappedNode<N>; 16]) -> [TrackedNode<N>; 16] {
    [
        TrackedNode::new(&underlying_children[0]),
        TrackedNode::new(&underlying_children[1]),
        TrackedNode::new(&underlying_children[2]),
        TrackedNode::new(&underlying_children[3]),
        TrackedNode::new(&underlying_children[4]),
        TrackedNode::new(&underlying_children[5]),
        TrackedNode::new(&underlying_children[6]),
        TrackedNode::new(&underlying_children[7]),
        TrackedNode::new(&underlying_children[8]),
        TrackedNode::new(&underlying_children[9]),
        TrackedNode::new(&underlying_children[10]),
        TrackedNode::new(&underlying_children[11]),
        TrackedNode::new(&underlying_children[12]),
        TrackedNode::new(&underlying_children[13]),
        TrackedNode::new(&underlying_children[14]),
        TrackedNode::new(&underlying_children[15]),
    ]
}

fn partial_trie_branch<N: TrieNode>(underlying_children: &[TrackedNode<N>; 16], value: &[u8]) -> N {
    let children = [
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[0],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[1],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[2],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[3],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[4],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[5],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[6],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[7],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[8],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[9],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[10],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[11],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[12],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[13],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[14],
        ))),
        Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            &underlying_children[15],
        ))),
    ];

    N::new(Node::Branch {
        children,
        value: value.to_owned(),
    })
}

#[derive(Debug)]
struct TrackedNodeInfo<N: TrieNode> {
    underlying_node: N,
    touched: bool,
}

impl<N: TrieNode> TrackedNodeInfo<N> {
    fn new(underlying_node: N) -> Self {
        Self {
            underlying_node,
            touched: false,
        }
    }

    fn reset(&mut self) {
        self.touched = false;
    }

    fn get_nibbles_expected(&self) -> &Nibbles {
        match &*self.underlying_node {
            Node::Extension { nibbles, .. } => nibbles,
            Node::Leaf { nibbles, .. } => nibbles,
            _ => unreachable!(
                "Tried getting the nibbles field from a {} node!",
                TrieNodeType::from(&*self.underlying_node)
            ),
        }
    }

    fn get_hash_node_hash_expected(&self) -> H256 {
        match *self.underlying_node {
            Node::Hash(h) => h,
            _ => unreachable!("Expected an underlying hash node!"),
        }
    }

    fn get_branch_value_expected(&self) -> &Vec<u8> {
        match &*self.underlying_node {
            Node::Branch { value, .. } => value,
            _ => unreachable!("Expected an underlying branch node!"),
        }
    }

    fn get_leaf_nibbles_and_value_expected(&self) -> (&Nibbles, &Vec<u8>) {
        match &*self.underlying_node {
            Node::Leaf { nibbles, value } => (nibbles, value),
            _ => unreachable!("Expected an underlying leaf node!"),
        }
    }
}

pub fn create_trie_subset<N, K>(
    trie: &N,
    keys_involved: impl Iterator<Item = K>,
) -> SubsetTrieResult<N>
where
    N: TrieNode,
    K: Into<Nibbles>,
{
    let mut tracked_trie = TrackedNode::new(trie);
    create_trie_subset_intern(&mut tracked_trie, keys_involved)
}

pub fn create_trie_subsets<N, K>(
    base_trie: &N,
    keys_involved: impl Iterator<Item = impl Iterator<Item = K>>,
) -> SubsetTrieResult<Vec<N>>
where
    N: TrieNode,
    K: Into<Nibbles>,
{
    let mut tracked_trie = TrackedNode::new(base_trie);

    keys_involved
        .map(|ks| {
            let res = create_trie_subset_intern(&mut tracked_trie, ks)?;
            reset_tracked_trie_state(&mut tracked_trie);

            Ok(res)
        })
        .collect::<SubsetTrieResult<_>>()
}

fn create_trie_subset_intern<N, K>(
    tracked_trie: &mut TrackedNode<N>,
    keys_involved: impl Iterator<Item = K>,
) -> SubsetTrieResult<N>
where
    N: TrieNode,
    K: Into<Nibbles>,
{
    for k in keys_involved {
        mark_nodes_that_are_needed(tracked_trie, &mut k.into())?;
    }

    Ok(create_partial_trie_subset_from_tracked_trie(tracked_trie))
}

fn mark_nodes_that_are_needed<N: TrieNode>(
    trie: &mut TrackedNode<N>,
    curr_nibbles: &mut Nibbles,
) -> SubsetTrieResult<()> {
    trie.info.touched = true;

    match &mut trie.node {
        TrackedNodeIntern::Empty | TrackedNodeIntern::Hash => Ok(()),
        // Note: If we end up supporting non-fixed sized keys, then we need to also check value.
        TrackedNodeIntern::Branch(children) => {
            // Check against branch value.
            if curr_nibbles.is_empty() {
                return Ok(());
            }

            let nib = curr_nibbles.pop_next_nibble_front();
            mark_nodes_that_are_needed(&mut children[nib as usize], curr_nibbles)
        }
        TrackedNodeIntern::Extension(child) => {
            let nibbles = child.info.get_nibbles_expected();
            let r = curr_nibbles.pop_nibbles_front(nibbles.count);

            match r.nibbles_are_identical_up_to_smallest_count(nibbles) {
                false => Ok(()),
                true => mark_nodes_that_are_needed(child, curr_nibbles),
            }
        }
        TrackedNodeIntern::Leaf => {
            let nibbles = trie.info.get_nibbles_expected();
            match nibbles.nibbles_are_identical_up_to_smallest_count(curr_nibbles) {
                false => Err(SubsetTrieError::UnexpectedKey(
                    *curr_nibbles,
                    format!("{:?}", trie),
                )),
                true => Ok(()),
            }
        }
    }
}

fn create_partial_trie_subset_from_tracked_trie<N: TrieNode>(tracked_node: &TrackedNode<N>) -> N {
    match tracked_node.info.touched {
        false => N::new(Node::Hash(tracked_node.info.underlying_node.hash())),
        true => match &tracked_node.node {
            TrackedNodeIntern::Empty => N::new(Node::Empty),
            TrackedNodeIntern::Hash => {
                N::new(Node::Hash(tracked_node.info.get_hash_node_hash_expected()))
            }
            TrackedNodeIntern::Branch(children) => {
                partial_trie_branch(children, tracked_node.info.get_branch_value_expected())
            }
            TrackedNodeIntern::Extension(child) => {
                create_partial_trie_subset_from_tracked_trie(child)
            }
            TrackedNodeIntern::Leaf => {
                let (nibbles, value) = tracked_node.info.get_leaf_nibbles_and_value_expected();
                N::new(Node::Leaf {
                    nibbles: *nibbles,
                    value: value.clone(),
                })
            }
        },
    }
}

fn reset_tracked_trie_state<N: TrieNode>(tracked_node: &mut TrackedNode<N>) {
    match tracked_node.node {
        TrackedNodeIntern::Branch(ref mut children) => {
            children.iter_mut().for_each(|c| c.info.reset())
        }
        TrackedNodeIntern::Extension(ref mut child) => child.info.reset(),
        TrackedNodeIntern::Empty | TrackedNodeIntern::Hash | TrackedNodeIntern::Leaf => {
            tracked_node.info.reset()
        }
    }
}
