//! Logic for calculating a subset of a [`PartialTrie`] from an existing
//! [`PartialTrie`].
//!
//! Given a `PartialTrie`, you can pass in keys of leaf nodes that should be
//! included in the produced subset. Any nodes that are not needed in the subset
//! are replaced with [`Hash`] nodes are far up the trie as possible.

use std::sync::Arc;

use ethereum_types::H256;
use thiserror::Error;

use crate::{
    nibbles::Nibbles,
    partial_trie::{Node, PartialTrie, WrappedNode},
    utils::TrieNodeType,
};

pub type SubsetTrieResult<T> = Result<T, SubsetTrieError>;

/// Errors that may occur when creating a subset [`PartialTrie`].
#[derive(Debug, Error)]
pub enum SubsetTrieError {
    #[error("Tried to mark nodes in a tracked trie for a key that does not exist! (Key: {0}, trie: {1})")]
    UnexpectedKey(Nibbles, String),
}

#[derive(Debug)]
enum TrackedNodeIntern<N: PartialTrie> {
    Empty,
    Hash,
    Branch(Box<[TrackedNode<N>; 16]>),
    Extension(Box<TrackedNode<N>>),
    Leaf,
}

#[derive(Debug)]
struct TrackedNode<N: PartialTrie> {
    node: TrackedNodeIntern<N>,
    info: TrackedNodeInfo<N>,
}

impl<N: Clone + PartialTrie> TrackedNode<N> {
    fn new(underlying_node: &N) -> Self {
        Self {
            node: match &**underlying_node {
                Node::Empty => TrackedNodeIntern::Empty,
                Node::Hash(_) => TrackedNodeIntern::Hash,
                Node::Branch { ref children, .. } => {
                    TrackedNodeIntern::Branch(Box::new(tracked_branch(children)))
                }
                Node::Extension { child, .. } => {
                    TrackedNodeIntern::Extension(Box::new(TrackedNode::new(child)))
                }
                Node::Leaf { .. } => TrackedNodeIntern::Leaf,
            },
            info: TrackedNodeInfo::new(underlying_node.clone()),
        }
    }
}

fn tracked_branch<N: PartialTrie>(
    underlying_children: &[WrappedNode<N>; 16],
) -> [TrackedNode<N>; 16] {
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

fn partial_trie_extension<N: PartialTrie>(nibbles: Nibbles, child: &TrackedNode<N>) -> N {
    N::new(Node::Extension {
        nibbles,
        child: Arc::new(Box::new(create_partial_trie_subset_from_tracked_trie(
            child,
        ))),
    })
}

fn partial_trie_branch<N: PartialTrie>(
    underlying_children: &[TrackedNode<N>; 16],
    value: &[u8],
) -> N {
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
struct TrackedNodeInfo<N: PartialTrie> {
    underlying_node: N,
    touched: bool,
}

impl<N: PartialTrie> TrackedNodeInfo<N> {
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

/// Create a [`PartialTrie`] subset from a base trie given a list of keys of
/// leaf nodes that must be present in the subset.
pub fn create_trie_subset<N, K, I>(trie: &N, keys_involved: I) -> SubsetTrieResult<N>
where
    N: PartialTrie,
    K: Into<Nibbles>,
    I: IntoIterator<Item = K>,
{
    let mut tracked_trie = TrackedNode::new(trie);
    create_trie_subset_intern(&mut tracked_trie, keys_involved.into_iter())
}

/// Create [`PartialTrie`] subsets from a given base `PartialTrie` given a
/// iterator of keys per subset needed.
pub fn create_trie_subsets<N, K, I, O>(base_trie: &N, keys_involved: O) -> SubsetTrieResult<Vec<N>>
where
    N: PartialTrie,
    K: Into<Nibbles>,
    I: IntoIterator<Item = K>,
    O: IntoIterator<Item = I>,
{
    let mut tracked_trie = TrackedNode::new(base_trie);

    keys_involved
        .into_iter()
        .map(|ks| {
            let res = create_trie_subset_intern(&mut tracked_trie, ks.into_iter())?;
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
    N: PartialTrie,
    K: Into<Nibbles>,
{
    for k in keys_involved {
        mark_nodes_that_are_needed(tracked_trie, &mut k.into())?;
    }

    Ok(create_partial_trie_subset_from_tracked_trie(tracked_trie))
}

fn mark_nodes_that_are_needed<N: PartialTrie>(
    trie: &mut TrackedNode<N>,
    curr_nibbles: &mut Nibbles,
) -> SubsetTrieResult<()> {
    trie.info.touched = true;

    match &mut trie.node {
        TrackedNodeIntern::Empty | TrackedNodeIntern::Hash => match curr_nibbles.is_empty() {
            false => Err(SubsetTrieError::UnexpectedKey(
                *curr_nibbles,
                format!("{:?}", trie),
            )),
            true => Ok(()),
        },
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
            let nibbles = trie.info.get_nibbles_expected();
            let r = curr_nibbles.pop_nibbles_front(nibbles.count);

            match r.nibbles_are_identical_up_to_smallest_count(nibbles) {
                false => Err(SubsetTrieError::UnexpectedKey(
                    *curr_nibbles,
                    format!("{:?}", trie),
                )),
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

fn create_partial_trie_subset_from_tracked_trie<N: PartialTrie>(
    tracked_node: &TrackedNode<N>,
) -> N {
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
                partial_trie_extension(*tracked_node.info.get_nibbles_expected(), child)
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

fn reset_tracked_trie_state<N: PartialTrie>(tracked_node: &mut TrackedNode<N>) {
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

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, iter::once};

    use super::{create_trie_subset, create_trie_subsets};
    use crate::{
        nibbles::Nibbles,
        partial_trie::{HashedPartialTrie, Node, PartialTrie},
        testing_utils::generate_n_random_fixed_trie_entries,
        trie_ops::ValOrHash,
        utils::TrieNodeType,
    };

    type TrieType = HashedPartialTrie;

    const MASSIVE_TEST_NUM_SUB_TRIES: usize = 10;
    const MASSIVE_TEST_NUM_SUB_TRIE_SIZE: usize = 5000;

    #[derive(Debug, Eq, PartialEq)]
    struct NodeFullNibbles {
        n_type: TrieNodeType,
        nibbles: Nibbles,
    }

    impl NodeFullNibbles {
        fn new_from_node<N: PartialTrie>(node: &Node<N>, nibbles: Nibbles) -> Self {
            Self {
                n_type: node.into(),
                nibbles,
            }
        }

        fn new_from_node_type<K: Into<Nibbles>>(n_type: TrieNodeType, nibbles: K) -> Self {
            Self {
                n_type,
                nibbles: nibbles.into(),
            }
        }
    }

    fn get_all_non_empty_and_hash_nodes_in_trie(trie: &TrieType) -> Vec<NodeFullNibbles> {
        let mut nodes = Vec::new();
        get_all_non_empty_and_hash_nodes_in_trie_intern(trie, Nibbles::default(), &mut nodes);

        nodes
    }

    fn get_all_non_empty_and_hash_nodes_in_trie_intern(
        trie: &TrieType,
        mut curr_nibbles: Nibbles,
        nodes: &mut Vec<NodeFullNibbles>,
    ) {
        match &trie.node {
            Node::Empty | Node::Hash(_) => return,
            Node::Branch { children, .. } => {
                for (i, c) in children.iter().enumerate() {
                    get_all_non_empty_and_hash_nodes_in_trie_intern(
                        c,
                        curr_nibbles.merge_nibble(i as u8),
                        nodes,
                    )
                }
            }
            Node::Extension { nibbles, child } => get_all_non_empty_and_hash_nodes_in_trie_intern(
                child,
                curr_nibbles.merge_nibbles(nibbles),
                nodes,
            ),
            Node::Leaf { nibbles, .. } => curr_nibbles = curr_nibbles.merge_nibbles(nibbles),
        };

        nodes.push(NodeFullNibbles::new_from_node(trie, curr_nibbles.reverse()));
    }

    fn get_all_nibbles_of_leaf_nodes_in_trie(trie: &TrieType) -> HashSet<Nibbles> {
        trie.items()
            .filter_map(|(n, v_or_h)| matches!(v_or_h, ValOrHash::Val(_)).then(|| n))
            .collect()
    }

    #[test]
    fn empty_trie_returns_err_on_query() {
        let trie = TrieType::default();
        let nibbles: Nibbles = 0x1234.into();
        let res = create_trie_subset(&trie, once(nibbles));

        assert!(res.is_err());
    }

    #[test]
    fn non_existent_key_returns_err() {
        let mut trie = TrieType::default();
        trie.insert(0x1234, vec![0, 1, 2]);
        let res = create_trie_subset(&trie, once(0x5678));

        assert!(res.is_err());
    }

    #[test]
    fn single_node_trie_is_queryable() {
        let mut trie = TrieType::default();
        trie.insert(0x1234, vec![0, 1, 2]);
        let trie_subset = create_trie_subset(&trie, once(0x1234)).unwrap();

        assert_eq!(trie, trie_subset);
    }

    #[test]
    fn multi_node_trie_returns_proper_subset() {
        let mut trie = TrieType::default();
        trie.insert(0x1234, vec![0]);
        trie.insert(0x56, vec![1]);
        trie.insert(0x12345, vec![2]);

        let trie_subset = create_trie_subset(&trie, vec![0x1234, 0x56].into_iter()).unwrap();
        let leaf_keys = get_all_nibbles_of_leaf_nodes_in_trie(&trie_subset);

        assert!(leaf_keys.contains(&(Nibbles::from(0x1234))));
        assert!(leaf_keys.contains(&(Nibbles::from(0x56))));
        assert!(!leaf_keys.contains(&Nibbles::from(0x12345)));
    }

    #[test]
    fn intermediate_nodes_are_included_in_subset() {
        let mut trie = TrieType::default();
        let inserts = vec![
            (0x1234_u64.into(), vec![0]),
            (0x1324_u64.into(), vec![1]),
            (0x132400005_u64.into(), vec![2]),
            (0x2001_u64.into(), vec![3]),
            (0x2002_u64.into(), vec![4]),
        ];

        // Branch (0x)  --> 1, 2
        // Branch (0x1) --> 2, 3
        // Leaf (0x1234) --> (n: 0x34, v: [0])

        // Branch (0x1324, v: [1]) --> 0
        // Leaf (0x132400005) --> (0x0005, v: [2])

        // Extension (0x2) --> n: 0x00
        // Branch (0x200) --> 1, 2
        // Leaf  (0x2001) --> (n: 0x1, v: [3])
        // Leaf  (0x2002) --> (n: 0x2, v: [4])

        for (k, v) in inserts.iter() {
            trie.insert(*k, v.clone());
        }

        let ks: Vec<_> = inserts.iter().map(|(k, _)| k).cloned().collect();
        let trie_subset_all = create_trie_subset(&trie, ks.iter().cloned()).unwrap();

        let subset_keys = get_all_nibbles_of_leaf_nodes_in_trie(&trie_subset_all);
        assert!(subset_keys.iter().all(|k| ks.contains(k)));
        assert!(ks.iter().all(|k| subset_keys.contains(k)));

        let all_non_empty_and_hash_nodes =
            get_all_non_empty_and_hash_nodes_in_trie(&trie_subset_all);
        println!("{:#?}", all_non_empty_and_hash_nodes);
        assert_node_exists(
            &all_non_empty_and_hash_nodes,
            TrieNodeType::Branch,
            Nibbles::default(),
        );
        assert_node_exists(&all_non_empty_and_hash_nodes, TrieNodeType::Branch, 0x1);
        assert_node_exists(&all_non_empty_and_hash_nodes, TrieNodeType::Leaf, 0x1234);

        assert_node_exists(&all_non_empty_and_hash_nodes, TrieNodeType::Extension, 0x13);
        assert_node_exists(&all_non_empty_and_hash_nodes, TrieNodeType::Branch, 0x1324);
        assert_node_exists(
            &all_non_empty_and_hash_nodes,
            TrieNodeType::Leaf,
            0x132400005_u64,
        );

        assert_node_exists(&all_non_empty_and_hash_nodes, TrieNodeType::Extension, 0x2);
        assert_node_exists(&all_non_empty_and_hash_nodes, TrieNodeType::Branch, 0x200);
        assert_node_exists(&all_non_empty_and_hash_nodes, TrieNodeType::Leaf, 0x2001);
        assert_node_exists(&all_non_empty_and_hash_nodes, TrieNodeType::Leaf, 0x2002);

        assert_eq!(all_non_empty_and_hash_nodes.len(), 10);

        // Now actual subset tests.
        let all_non_empty_and_hash_nodes_partial = get_all_non_empty_and_hash_nodes_in_trie(
            &create_trie_subset(&trie, once(0x2001)).unwrap(),
        );
        assert_node_exists(
            &all_non_empty_and_hash_nodes_partial,
            TrieNodeType::Branch,
            Nibbles::default(),
        );
        assert_node_exists(
            &all_non_empty_and_hash_nodes_partial,
            TrieNodeType::Extension,
            0x2,
        );
        assert_node_exists(
            &all_non_empty_and_hash_nodes_partial,
            TrieNodeType::Branch,
            0x200,
        );
        assert_node_exists(
            &all_non_empty_and_hash_nodes_partial,
            TrieNodeType::Leaf,
            0x2001,
        );
        assert_eq!(all_non_empty_and_hash_nodes_partial.len(), 4);

        let all_non_empty_and_hash_nodes_partial = get_all_non_empty_and_hash_nodes_in_trie(
            &create_trie_subset(&trie, once(0x1324)).unwrap(),
        );
        assert_node_exists(
            &all_non_empty_and_hash_nodes_partial,
            TrieNodeType::Branch,
            Nibbles::default(),
        );
        assert_node_exists(
            &all_non_empty_and_hash_nodes_partial,
            TrieNodeType::Branch,
            0x1,
        );
        assert_node_exists(
            &all_non_empty_and_hash_nodes_partial,
            TrieNodeType::Extension,
            0x13,
        );
        assert_node_exists(
            &all_non_empty_and_hash_nodes_partial,
            TrieNodeType::Branch,
            0x1324,
        );
        assert_eq!(all_non_empty_and_hash_nodes_partial.len(), 4);
    }

    fn assert_node_exists<K: Into<Nibbles>>(
        nodes: &[NodeFullNibbles],
        n_type: TrieNodeType,
        nibbles: K,
    ) {
        assert!(nodes.contains(&NodeFullNibbles::new_from_node_type(
            n_type,
            nibbles.into().reverse()
        )));
    }

    #[test]
    fn all_leafs_of_keys_to_create_subset_are_included_in_subset_for_giant_trie() {
        let trie_size = MASSIVE_TEST_NUM_SUB_TRIES * MASSIVE_TEST_NUM_SUB_TRIE_SIZE;

        let random_entries: Vec<_> =
            generate_n_random_fixed_trie_entries(trie_size, 9009).collect();
        let entry_keys: Vec<_> = random_entries.iter().map(|(k, _)| k).cloned().collect();
        let trie = TrieType::from_iter(random_entries);

        let keys_of_subsets: Vec<Vec<_>> = (0..MASSIVE_TEST_NUM_SUB_TRIES)
            .map(|i| {
                let entry_range_start = i * MASSIVE_TEST_NUM_SUB_TRIE_SIZE;
                let entry_range_end = entry_range_start + MASSIVE_TEST_NUM_SUB_TRIE_SIZE;
                entry_keys[entry_range_start..entry_range_end].to_vec()
            })
            .collect();

        let trie_subsets =
            create_trie_subsets(&trie, keys_of_subsets.iter().map(|v| v.iter().cloned())).unwrap();

        for (sub_trie, ks_used) in trie_subsets.into_iter().zip(keys_of_subsets.into_iter()) {
            let leaf_nibbles = get_all_nibbles_of_leaf_nodes_in_trie(&sub_trie);
            assert!(ks_used.into_iter().all(|k| leaf_nibbles.contains(&k)));
        }
    }
}
