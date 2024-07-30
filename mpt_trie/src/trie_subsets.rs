//! Logic for calculating a subset of a [`PartialTrie`] from an existing
//! [`PartialTrie`].
//!
//! Given a `PartialTrie`, you can pass in keys of leaf nodes that should be
//! included in the produced subset. Any nodes that are not needed in the subset
//! are replaced with [`Hash`] nodes are far up the trie as possible.

use std::sync::Arc;

use ethereum_types::H256;
use log::trace;
use thiserror::Error;

use crate::{
    nibbles::Nibbles,
    partial_trie::{Node, PartialTrie, WrappedNode},
    trie_hashing::EncodedNode,
    utils::{bytes_to_h256, TrieNodeType},
};

/// The output type of trie_subset operations.
pub type SubsetTrieResult<T> = Result<T, SubsetTrieError>;

/// Errors that may occur when creating a subset [`PartialTrie`].
#[derive(Clone, Debug, Error, Hash)]
pub enum SubsetTrieError {
    #[error("Tried to mark nodes in a tracked trie for a key that does not exist! (Key: {0}, trie: {1})")]
    /// The key does not exist in the trie.
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
    const fn new(underlying_node: N) -> Self {
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

/// Create a [`PartialTrie`] subset from a base trie given an iterator of keys
/// of nodes that may or may not exist in the trie. All nodes traversed by the
/// keys will not be hashed out in the trie subset. If the key does not exist in
/// the trie at all, this is not considered an error and will still record which
/// nodes were visited.
pub fn create_trie_subset<N, K>(
    trie: &N,
    keys_involved: impl IntoIterator<Item = K>,
) -> SubsetTrieResult<N>
where
    N: PartialTrie,
    K: Into<Nibbles>,
{
    let mut tracked_trie = TrackedNode::new(trie);
    create_trie_subset_intern(&mut tracked_trie, keys_involved.into_iter())
}

/// Create [`PartialTrie`] subsets from a given base `PartialTrie` given a
/// iterator of keys per subset needed. See [`create_trie_subset`] for more
/// info.
pub fn create_trie_subsets<N, K>(
    base_trie: &N,
    keys_involved: impl IntoIterator<Item = impl IntoIterator<Item = K>>,
) -> SubsetTrieResult<Vec<N>>
where
    N: PartialTrie,
    K: Into<Nibbles>,
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

/// For a given key, mark every node that we encounter that is part of the key.
/// Note that this means non-existent keys passed into this function will mark
/// nodes to not be hashed that are part of the given key. For example:
/// - Relevant nodes in trie: [B(0x), B(0x1), L(0x123)]
/// - For the key `0x1`, the marked nodes would be [B(0x), B(0x1)].
/// - For the key `0x12`, the marked nodes still would be [B(0x), B(0x1)].
/// - For the key `0x123`, the marked nodes would be [B(0x), B(0x1), L(0x123)].
fn mark_nodes_that_are_needed<N: PartialTrie>(
    trie: &mut TrackedNode<N>,
    curr_nibbles: &mut Nibbles,
) -> SubsetTrieResult<()> {
    trace!(
        "Sub-trie marking at {:x}, (type: {})",
        curr_nibbles,
        TrieNodeType::from(trie.info.underlying_node.deref())
    );

    match &mut trie.node {
        TrackedNodeIntern::Empty => {
            trie.info.touched = true;
        }
        TrackedNodeIntern::Hash => match curr_nibbles.is_empty() {
            false => {
                return Err(SubsetTrieError::UnexpectedKey(
                    *curr_nibbles,
                    format!("{:?}", trie),
                ));
            }
            true => {
                trie.info.touched = true;
            }
        },
        // Note: If we end up supporting non-fixed sized keys, then we need to also check value.
        TrackedNodeIntern::Branch(children) => {
            trie.info.touched = true;

            // Check against branch value.
            if curr_nibbles.is_empty() {
                return Ok(());
            }

            let nib = curr_nibbles.pop_next_nibble_front();
            return mark_nodes_that_are_needed(&mut children[nib as usize], curr_nibbles);
        }
        TrackedNodeIntern::Extension(child) => {
            // If we hit an extension node, we always must include it unless we exhausted
            // our key.
            if curr_nibbles.is_empty() {
                return Ok(());
            }

            trie.info.touched = true;

            let nibbles: &Nibbles = trie.info.get_nibbles_expected();
            if curr_nibbles.nibbles_are_identical_up_to_smallest_count(nibbles) {
                curr_nibbles.pop_nibbles_front(nibbles.count);
                return mark_nodes_that_are_needed(child, curr_nibbles);
            }
        }
        TrackedNodeIntern::Leaf => {
            trie.info.touched = true;
        }
    }

    Ok(())
}

fn create_partial_trie_subset_from_tracked_trie<N: PartialTrie>(
    tracked_node: &TrackedNode<N>,
) -> N {
    // If we don't use the node in the trace, then we can potentially hash it away.
    if !tracked_node.info.touched {
        let e_node = tracked_node.info.underlying_node.hash_intern();

        // Don't hash if it's too small, even if we don't need it.
        if let EncodedNode::Hashed(h) = e_node {
            return N::new(Node::Hash(bytes_to_h256(&h)));
        }
    }

    match &tracked_node.node {
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
    }
}

fn reset_tracked_trie_state<N: PartialTrie>(tracked_node: &mut TrackedNode<N>) {
    match tracked_node.node {
        TrackedNodeIntern::Branch(ref mut children) => children.iter_mut().for_each(|c| {
            c.info.reset();
            reset_tracked_trie_state(c);
        }),
        TrackedNodeIntern::Extension(ref mut child) => {
            child.info.reset();
            reset_tracked_trie_state(child);
        }
        TrackedNodeIntern::Empty | TrackedNodeIntern::Hash | TrackedNodeIntern::Leaf => {
            tracked_node.info.reset()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        iter::once,
    };

    use ethereum_types::H256;

    use super::{create_trie_subset, create_trie_subsets};
    use crate::{
        nibbles::Nibbles,
        partial_trie::{Node, PartialTrie},
        testing_utils::{
            common_setup, create_trie_with_large_entry_nodes,
            generate_n_random_fixed_trie_value_entries, handmade_trie_1, TrieType,
        },
        trie_ops::{TrieOpResult, ValOrHash},
        utils::{TrieNodeType, TryFromIterator},
    };

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

    fn get_all_nodes_in_trie(trie: &TrieType) -> Vec<NodeFullNibbles> {
        get_nodes_in_trie_intern(trie, false)
    }

    fn get_all_non_empty_and_hash_nodes_in_trie(trie: &TrieType) -> Vec<NodeFullNibbles> {
        get_nodes_in_trie_intern(trie, true)
    }

    fn get_nodes_in_trie_intern(
        trie: &TrieType,
        return_on_empty_or_hash: bool,
    ) -> Vec<NodeFullNibbles> {
        let mut nodes = Vec::new();
        get_nodes_in_trie_intern_rec(
            trie,
            Nibbles::default(),
            &mut nodes,
            return_on_empty_or_hash,
        );

        nodes
    }

    fn get_nodes_in_trie_intern_rec(
        trie: &TrieType,
        mut curr_nibbles: Nibbles,
        nodes: &mut Vec<NodeFullNibbles>,
        return_on_empty_or_hash: bool,
    ) {
        match &trie.node {
            Node::Empty | Node::Hash(_) => match return_on_empty_or_hash {
                false => (),
                true => return,
            },
            Node::Branch { children, .. } => {
                for (i, c) in children.iter().enumerate() {
                    get_nodes_in_trie_intern_rec(
                        c,
                        curr_nibbles.merge_nibble(i as u8),
                        nodes,
                        return_on_empty_or_hash,
                    )
                }
            }
            Node::Extension { nibbles, child } => get_nodes_in_trie_intern_rec(
                child,
                curr_nibbles.merge_nibbles(nibbles),
                nodes,
                return_on_empty_or_hash,
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
    fn empty_trie_does_not_return_err_on_query() {
        common_setup();

        let trie = TrieType::default();
        let nibbles: Nibbles = 0x1234.into();
        let res = create_trie_subset(&trie, once(nibbles));

        assert!(res.is_ok());
    }

    #[test]
    fn non_existent_key_does_not_return_err() {
        common_setup();

        let mut trie = TrieType::default();
        assert!(trie.insert(0x1234, vec![0, 1, 2]).is_ok());
        let res = create_trie_subset(&trie, once(0x5678));

        assert!(res.is_ok());
    }

    #[test]
    fn encountering_a_hash_node_returns_err() {
        common_setup();

        let trie = TrieType::new(Node::Hash(H256::zero()));
        let res = create_trie_subset(&trie, once(0x1234));

        assert!(res.is_err())
    }

    #[test]
    fn single_node_trie_is_queryable() -> Result<(), Box<dyn std::error::Error>> {
        common_setup();

        let mut trie = TrieType::default();
        trie.insert(0x1234, vec![0, 1, 2])?;
        let trie_subset = create_trie_subset(&trie, once(0x1234))?;

        assert_eq!(trie, trie_subset);

        Ok(())
    }

    #[test]
    fn multi_node_trie_returns_proper_subset() -> Result<(), Box<dyn std::error::Error>> {
        common_setup();

        let trie = create_trie_with_large_entry_nodes(&[0x1234, 0x56, 0x12345_u64])?;

        let trie_subset = create_trie_subset(&trie, vec![0x1234, 0x56])?;
        let leaf_keys = get_all_nibbles_of_leaf_nodes_in_trie(&trie_subset);

        assert!(leaf_keys.contains(&(Nibbles::from(0x1234))));
        assert!(leaf_keys.contains(&(Nibbles::from(0x56))));
        assert!(!leaf_keys.contains(&Nibbles::from(0x12345)));

        Ok(())
    }

    #[test]
    fn intermediate_nodes_are_included_in_subset() {
        common_setup();

        let (trie, ks_nibbles) = handmade_trie_1().unwrap();
        let trie_subset_all = create_trie_subset(&trie, ks_nibbles.iter().cloned()).unwrap();

        let subset_keys = get_all_nibbles_of_leaf_nodes_in_trie(&trie_subset_all);
        assert!(subset_keys.iter().all(|k| ks_nibbles.contains(k)));
        assert!(ks_nibbles.iter().all(|k| subset_keys.contains(k)));

        let all_non_empty_and_hash_nodes =
            get_all_non_empty_and_hash_nodes_in_trie(&trie_subset_all);

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

    fn assert_nodes_are_leaf_nodes<K: Clone + Into<Nibbles>, I: IntoIterator<Item = K>>(
        trie: &TrieType,
        keys: I,
    ) {
        assert_keys_point_to_nodes_of_type(
            trie,
            keys.into_iter().map(|k| (k.into(), TrieNodeType::Leaf)),
        )
    }

    fn assert_nodes_are_hash_nodes<K: Clone + Into<Nibbles>, I: IntoIterator<Item = K>>(
        trie: &TrieType,
        keys: I,
    ) {
        assert_keys_point_to_nodes_of_type(
            trie,
            keys.into_iter().map(|k| (k.into(), TrieNodeType::Hash)),
        )
    }

    fn assert_keys_point_to_nodes_of_type(
        trie: &TrieType,
        keys: impl Iterator<Item = (Nibbles, TrieNodeType)>,
    ) {
        let nodes = get_all_nodes_in_trie(trie);
        let keys_to_node_types: HashMap<_, _> =
            HashMap::from_iter(nodes.into_iter().map(|n| (n.nibbles.reverse(), n.n_type)));

        for (k, expected_n_type) in keys {
            let actual_n_type_opt = keys_to_node_types.get(&k);

            match actual_n_type_opt {
                Some(actual_n_type) => {
                    if *actual_n_type != expected_n_type {
                        panic!("Expected trie node at {:x} to be a {} node but it wasn't! (found a {} node instead)", k, expected_n_type, actual_n_type)
                    }
                }
                None => panic!(
                    "Expected a {} node at {:x} but no node was found!",
                    expected_n_type, k
                ),
            }
        }
    }

    #[test]
    fn all_leafs_of_keys_to_create_subset_are_included_in_subset_for_giant_trie() -> TrieOpResult<()>
    {
        common_setup();

        let (_, trie_subsets, keys_of_subsets) = create_massive_trie_and_subsets(9009)?;

        for (sub_trie, ks_used) in trie_subsets.into_iter().zip(keys_of_subsets.into_iter()) {
            let leaf_nibbles = get_all_nibbles_of_leaf_nodes_in_trie(&sub_trie);
            assert!(ks_used.into_iter().all(|k| leaf_nibbles.contains(&k)));
        }

        Ok(())
    }

    #[test]
    fn hash_of_single_leaf_trie_partial_trie_matches_original_trie() {
        let trie = create_trie_with_large_entry_nodes(&[0x0]).unwrap();

        let base_hash = trie.hash();
        let partial_trie = create_trie_subset(&trie, [0x1234]).unwrap();

        assert_eq!(base_hash, partial_trie.hash());
    }

    #[test]
    fn sub_trie_that_includes_branch_but_not_children_hashes_out_children() {
        common_setup();

        let trie =
            create_trie_with_large_entry_nodes(&[0x1234, 0x12345, 0x12346, 0x1234f]).unwrap();
        let partial_trie = create_trie_subset(&trie, [0x1234f]).unwrap();

        assert_nodes_are_hash_nodes(&partial_trie, [0x12345, 0x12346]);
    }

    #[test]
    fn sub_trie_for_non_existent_key_that_hits_branch_leaf_does_not_hash_out_leaf(
    ) -> TrieOpResult<()> {
        common_setup();

        let trie = create_trie_with_large_entry_nodes(&[0x1234, 0x1234589, 0x12346])?;
        let partial_trie = create_trie_subset(&trie, [0x1234567]).unwrap();

        // Note that `0x1234589` gets hashed at the branch slot at `0x12345`.
        assert_nodes_are_hash_nodes(&partial_trie, Vec::<Nibbles>::default());

        Ok(())
    }

    #[test]
    fn hash_of_branch_partial_tries_matches_original_trie() -> TrieOpResult<()> {
        common_setup();
        let trie = create_trie_with_large_entry_nodes(&[0x1234, 0x56, 0x12345])?;

        let base_hash: H256 = trie.hash();
        let partial_tries = vec![
            create_trie_subset(&trie, vec![0x1234]).unwrap(),
            create_trie_subset(&trie, vec![0x56]).unwrap(),
            create_trie_subset(&trie, vec![0x2]).unwrap(),
            create_trie_subset(&trie, vec![0x1234, 0x12345]).unwrap(),
            create_trie_subset(&trie, vec![0x1234, 0x56, 0x12345]).unwrap(),
        ];
        assert!(partial_tries
            .into_iter()
            .all(|p_tree| p_tree.hash() == base_hash));

        Ok(())
    }

    #[test]
    fn hash_of_giant_random_partial_tries_matches_original_trie() -> TrieOpResult<()> {
        common_setup();

        let (base_trie, trie_subsets, _) = create_massive_trie_and_subsets(9010)?;
        let base_hash = base_trie.hash();

        assert!(trie_subsets
            .into_iter()
            .all(|p_tree| p_tree.hash() == base_hash));

        Ok(())
    }

    #[test]
    fn giant_random_partial_tries_hashes_leaves_correctly() -> TrieOpResult<()> {
        common_setup();

        let (base_trie, trie_subsets, leaf_keys_per_trie) = create_massive_trie_and_subsets(9011)?;
        let all_keys: Vec<Nibbles> = base_trie.keys().collect();

        for (partial_trie, leaf_trie_keys) in
            trie_subsets.into_iter().zip(leaf_keys_per_trie.into_iter())
        {
            let leaf_keys_lookup: HashSet<Nibbles> = leaf_trie_keys.iter().cloned().collect();
            let keys_of_hash_nodes = all_keys
                .iter()
                .filter(|k| !leaf_keys_lookup.contains(k))
                .cloned();

            assert_nodes_are_leaf_nodes(&partial_trie, leaf_trie_keys);

            // We have no idea were the paths to the hashed out nodes will start in the
            // trie, so the best we can do is to check that they don't exist (if we traverse
            // over a `Hash` node, we return `None`.)
            assert_all_keys_do_not_exist(&partial_trie, keys_of_hash_nodes);
        }

        Ok(())
    }

    #[test]
    fn sub_trie_existent_key_contains_returns_true() {
        let trie = create_trie_with_large_entry_nodes(&[0x0]).unwrap();

        let partial_trie = create_trie_subset(&trie, [0x1234]).unwrap();

        assert!(partial_trie.contains(0x0));
    }

    #[test]
    fn sub_trie_non_existent_key_contains_returns_false() {
        let trie = create_trie_with_large_entry_nodes(&[0x0]).unwrap();

        let partial_trie = create_trie_subset(&trie, [0x1234]).unwrap();

        assert!(!partial_trie.contains(0x1));
    }

    fn assert_all_keys_do_not_exist(trie: &TrieType, ks: impl Iterator<Item = Nibbles>) {
        for k in ks {
            assert!(trie.get(k).is_none());
        }
    }

    fn create_massive_trie_and_subsets(
        seed: u64,
    ) -> TrieOpResult<(TrieType, Vec<TrieType>, Vec<Vec<Nibbles>>)> {
        let trie_size = MASSIVE_TEST_NUM_SUB_TRIES * MASSIVE_TEST_NUM_SUB_TRIE_SIZE;

        let random_entries: Vec<_> =
            generate_n_random_fixed_trie_value_entries(trie_size, seed).collect();
        let entry_keys: Vec<_> = random_entries.iter().map(|(k, _)| k).cloned().collect();
        let trie = TrieType::try_from_iter(random_entries)?;

        let keys_of_subsets: Vec<Vec<_>> = (0..MASSIVE_TEST_NUM_SUB_TRIES)
            .map(|i| {
                let entry_range_start = i * MASSIVE_TEST_NUM_SUB_TRIE_SIZE;
                let entry_range_end = entry_range_start + MASSIVE_TEST_NUM_SUB_TRIE_SIZE;
                entry_keys[entry_range_start..entry_range_end].to_vec()
            })
            .collect();

        let trie_subsets =
            create_trie_subsets(&trie, keys_of_subsets.iter().map(|v| v.iter().cloned())).unwrap();

        Ok((trie, trie_subsets, keys_of_subsets))
    }
}
