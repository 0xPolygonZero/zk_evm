//! Diffing tools to compare two tries against each other. Useful when you want
//! to find where the tries diverge from one each other.
//!
//! There are a few considerations when implementing the logic to create a trie
//! diff:
//! - What should be reported when the trie node structures diverge (eg. two
//!   different node types proceeding a given common node)?
//! - If there are multiple structural differences, how do we discover the
//!   smallest difference to report back?
//!
//! If the node types between the tries (structure) are identical but some
//! values are different, then these types of diffs are easy to detect and
//! report the lowest difference. Structural differences are more challenging
//! and a bit hard to report well. There are two approaches (only one currently
//! is implemented) in how to detect structural differences:
//! - Top-down search
//! - Bottom-up search
//!
//! These two searches are somewhat self-explanatory:
//! - Top-down will find the highest point of a structural divergence and report
//!   it. If there are multiple divergences, then only the one that is the
//!   highest in the trie will be reported.
//! - Bottom-up is a lot more complex to implement, but will attempt to find the
//!   smallest structural trie difference between the trie. If there are
//!   multiple differences, then this will likely be what you want to use.

use std::fmt::{self, Debug};
use std::{fmt::Display, ops::Deref};

use ethereum_types::H256;

use crate::utils::{get_segment_from_node_and_key_piece, TriePath};
use crate::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
    utils::TrieNodeType,
};

/// Get the key piece from the given node if applicable. Note that
/// [branch][`Node::Branch`]s have no [`Nibble`] directly associated with them.
fn get_key_piece_from_node<T: PartialTrie>(n: &Node<T>) -> Nibbles {
    match n {
        Node::Empty | Node::Hash(_) | Node::Branch { .. } => Nibbles::default(),
        Node::Extension { nibbles, child: _ } | Node::Leaf { nibbles, value: _ } => *nibbles,
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
/// The difference between two Tries, represented as the highest
/// array of `DiffPoint`s.
pub struct TrieDiff {
    /// Diff points between the two tries.
    pub diff_points: Vec<DiffPoint>,
}

impl Display for TrieDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, diff_point) in self.diff_points.iter().enumerate() {
            writeln!(f, "{}: {}\n", index, diff_point)?;
        }

        Ok(())
    }
}

#[derive(Copy, Clone, Debug)]
enum DiffDetectionState {
    NodeTypesDiffer = 0, // Also implies that hashes differ.
    HashDiffDetected,
    NoDiffDetected,
}

impl DiffDetectionState {
    const fn pick_most_significant_state(&self, other: &Self) -> Self {
        match self.get_int_repr() > other.get_int_repr() {
            false => *other,
            true => *self,
        }
    }

    /// The integer representation also indicates the more "significant" state.
    const fn get_int_repr(self) -> usize {
        self as usize
    }
}

/// A point (node) between the two tries where the children differ.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DiffPoint {
    /// The depth of the point in both tries.
    pub depth: usize,
    /// The path of the point in both tries.
    pub path: TriePath,
    /// The node key in both tries.
    pub key: Nibbles,
    /// The node info in the first trie.
    pub a_info: NodeInfo,
    /// The node info in the second trie.
    pub b_info: NodeInfo,
}

impl DiffPoint {
    fn new(
        child_a: &HashedPartialTrie,
        child_b: &HashedPartialTrie,
        parent_k: Nibbles,
        path: TriePath,
    ) -> Self {
        let a_key = parent_k.merge_nibbles(&get_key_piece_from_node(child_a));
        let b_key = parent_k.merge_nibbles(&get_key_piece_from_node(child_b));

        DiffPoint {
            depth: 0,
            path,
            key: parent_k,
            a_info: NodeInfo::new(child_a, a_key, get_value_from_node(child_a).cloned()),
            b_info: NodeInfo::new(child_b, b_key, get_value_from_node(child_b).cloned()),
        }
    }
}

impl Display for DiffPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Point Diff {{")?;
        writeln!(f, "    Depth: {},", self.depth)?;
        writeln!(f, "    Path: ({}),", self.path)?;
        writeln!(f, "    Key: {:x},", self.key)?;
        writeln!(f, "    A info: {},", self.a_info)?;
        writeln!(f, "    B info: {}", self.b_info)?;
        write!(f, "}}")
    }
}

/// Meta information for a node in a trie.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NodeInfo {
    /// Mpt trie node key.
    pub key: Nibbles,
    /// The direct value associated with the node (only applicable to `Leaf` &
    /// `Branch` nodes).
    pub value: Option<Vec<u8>>,
    /// Type of this node.
    pub node_type: TrieNodeType,
    /// Node hash.
    pub hash: H256,
}

impl Display for NodeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeInfo {{ Key: 0x{:x}, ", self.key)?;

        match &self.value {
            Some(v) => write!(f, "Value: 0x{}, ", hex::encode(v))?,
            None => write!(f, "Value: N/A, ")?,
        }

        write!(
            f,
            "Node type: {}, Trie hash: 0x{:x} }}",
            self.node_type, self.hash
        )
    }
}

impl NodeInfo {
    fn new(n: &HashedPartialTrie, key: Nibbles, value: Option<Vec<u8>>) -> Self {
        Self {
            key,
            value,
            node_type: n.deref().into(),
            hash: n.hash(),
        }
    }
}

/// Create a diff between two tries. Will perform both types of diff searches
/// (top-down & bottom-up). It will not stop on first difference.
pub fn create_full_diff_between_tries(a: &HashedPartialTrie, b: &HashedPartialTrie) -> TrieDiff {
    TrieDiff {
        diff_points: find_all_diff_points_between_tries(a, b),
    }
}

fn find_all_diff_points_between_tries(
    a: &HashedPartialTrie,
    b: &HashedPartialTrie,
) -> Vec<DiffPoint> {
    let state = DepthDiffPerCallState::new(a, b, Nibbles::default(), 0);
    let mut longest_states = Vec::new();

    find_all_diff_points_between_tries_rec(&state, &mut longest_states);

    longest_states
        .into_iter()
        .filter_map(|longest_state| {
            longest_state
                .longest_key_node_diff
                .or(longest_state.longest_key_hash_diff)
        })
        .collect()
}

#[derive(Debug, Default)]
struct DepthNodeDiffState {
    longest_key_node_diff: Option<DiffPoint>,
    longest_key_hash_diff: Option<DiffPoint>,
}

impl DepthNodeDiffState {
    fn try_update_longest_divergence_key_hash(&mut self, state: &DepthDiffPerCallState) {
        Self::replace_longest_field_if_our_key_is_larger(
            &mut self.longest_key_hash_diff,
            &state.curr_key,
            state.a,
            state.b,
            state.curr_path.clone(),
        );
    }

    fn try_update_longest_divergence_key_node(&mut self, state: &DepthDiffPerCallState) {
        Self::replace_longest_field_if_our_key_is_larger(
            &mut self.longest_key_node_diff,
            &state.curr_key,
            state.a,
            state.b,
            state.curr_path.clone(),
        );
    }

    fn replace_longest_field_if_our_key_is_larger(
        field: &mut Option<DiffPoint>,
        parent_k: &Nibbles,
        child_a: &HashedPartialTrie,
        child_b: &HashedPartialTrie,
        path: TriePath,
    ) {
        if field
            .as_ref()
            .map_or(true, |d_point| d_point.key.count < parent_k.count)
        {
            *field = Some(DiffPoint::new(child_a, child_b, *parent_k, path));
        }
    }
}

/// State that is copied per recursive call.
#[derive(Clone, Debug)]
struct DepthDiffPerCallState<'a> {
    a: &'a HashedPartialTrie,
    b: &'a HashedPartialTrie,
    curr_key: Nibbles,
    curr_depth: usize,

    // Horribly inefficient, but these are debug tools, so I think we get a pass.
    curr_path: TriePath,
}

impl<'a> DepthDiffPerCallState<'a> {
    /// Exists solely to prevent construction of this type from going over
    /// multiple lines.
    fn new(
        a: &'a HashedPartialTrie,
        b: &'a HashedPartialTrie,
        curr_key: Nibbles,
        curr_depth: usize,
    ) -> Self {
        Self {
            a,
            b,
            curr_key,
            curr_depth,
            curr_path: TriePath::default(),
        }
    }

    /// Note: The assumption here is that `a` and `b` are of the same node type
    /// and have the key.
    fn new_from_parent(
        &self,
        a: &'a HashedPartialTrie,
        b: &'a HashedPartialTrie,
        key_piece: &Nibbles,
    ) -> Self {
        let new_segment = get_segment_from_node_and_key_piece(self.a, key_piece);
        let new_path = self.curr_path.dup_and_append(new_segment);

        Self {
            a,
            b,
            curr_key: self.curr_key.merge_nibbles(key_piece),
            curr_depth: self.curr_depth + 1,
            curr_path: new_path,
        }
    }
}

// Search for the differences between two tries. Do not stop on first
// difference.
fn find_all_diff_points_between_tries_rec(
    state: &DepthDiffPerCallState,
    depth_states: &mut Vec<DepthNodeDiffState>,
) -> DiffDetectionState {
    let a_hash = state.a.hash();
    let b_hash = state.b.hash();

    // We're going to ignore node type differences if they have the same hash (only
    // case I think where this can happen is if one is a hash node?).
    if a_hash == b_hash {
        return DiffDetectionState::NoDiffDetected;
    }

    let a_type: TrieNodeType = state.a.deref().into();
    let b_type: TrieNodeType = state.b.deref().into();

    let a_key_piece = get_key_piece_from_node(state.a);
    let b_key_piece = get_key_piece_from_node(state.b);

    // Note that differences in a node's `value` will be picked up by a hash
    // mismatch.
    let mut current_depth_node_diff_state: DepthNodeDiffState = Default::default();
    if (a_type, a_key_piece) != (b_type, b_key_piece) {
        current_depth_node_diff_state.try_update_longest_divergence_key_node(state);
        depth_states.push(current_depth_node_diff_state);
        DiffDetectionState::NodeTypesDiffer
    } else {
        match (&state.a.node, &state.b.node) {
            (Node::Empty, Node::Empty) => DiffDetectionState::NoDiffDetected,
            (Node::Hash(a_hash), Node::Hash(b_hash)) => {
                match create_diff_detection_state_based_from_hashes(
                    a_hash,
                    b_hash,
                    &state.new_from_parent(state.a, state.b, &Nibbles::default()),
                    &mut current_depth_node_diff_state,
                ) {
                    DiffDetectionState::NoDiffDetected => DiffDetectionState::NoDiffDetected,
                    result @ (DiffDetectionState::HashDiffDetected
                    | DiffDetectionState::NodeTypesDiffer) => {
                        depth_states.push(current_depth_node_diff_state);
                        result
                    }
                }
            }
            (
                Node::Branch {
                    children: a_children,
                    value: _a_value,
                },
                Node::Branch {
                    children: b_children,
                    value: _b_value,
                },
            ) => {
                let mut most_significant_diff_found = DiffDetectionState::NoDiffDetected;

                for i in 0..16_usize {
                    let res = find_all_diff_points_between_tries_rec(
                        &state.new_from_parent(
                            &a_children[i],
                            &b_children[i],
                            &Nibbles::from_nibble(i as u8),
                        ),
                        depth_states,
                    );
                    most_significant_diff_found =
                        most_significant_diff_found.pick_most_significant_state(&res);
                }

                if matches!(
                    most_significant_diff_found,
                    DiffDetectionState::NoDiffDetected
                ) {
                    most_significant_diff_found
                } else {
                    // Also run a hash check if we haven't picked anything up
                    match create_diff_detection_state_based_from_hash_and_gen_hashes(
                        state,
                        &mut current_depth_node_diff_state,
                    ) {
                        DiffDetectionState::NoDiffDetected => DiffDetectionState::NoDiffDetected,
                        result @ (DiffDetectionState::HashDiffDetected
                        | DiffDetectionState::NodeTypesDiffer) => {
                            depth_states.push(current_depth_node_diff_state);
                            result
                        }
                    }
                }
            }
            (
                Node::Extension {
                    nibbles: a_nibs,
                    child: a_child,
                },
                Node::Extension {
                    nibbles: _b_nibs,
                    child: b_child,
                },
            ) => find_all_diff_points_between_tries_rec(
                &state.new_from_parent(a_child, b_child, a_nibs),
                depth_states,
            ),
            (Node::Leaf { .. }, Node::Leaf { .. }) => {
                match create_diff_detection_state_based_from_hash_and_gen_hashes(
                    state,
                    &mut current_depth_node_diff_state,
                ) {
                    DiffDetectionState::NoDiffDetected => DiffDetectionState::NoDiffDetected,
                    result @ (DiffDetectionState::HashDiffDetected
                    | DiffDetectionState::NodeTypesDiffer) => {
                        depth_states.push(current_depth_node_diff_state);
                        result
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}

fn create_diff_detection_state_based_from_hash_and_gen_hashes(
    state: &DepthDiffPerCallState,
    depth_state: &mut DepthNodeDiffState,
) -> DiffDetectionState {
    let a_hash = state.a.hash();
    let b_hash = state.b.hash();

    create_diff_detection_state_based_from_hashes(&a_hash, &b_hash, state, depth_state)
}

fn create_diff_detection_state_based_from_hashes(
    a_hash: &H256,
    b_hash: &H256,
    state: &DepthDiffPerCallState,
    depth_state: &mut DepthNodeDiffState,
) -> DiffDetectionState {
    match a_hash == b_hash {
        false => {
            depth_state.try_update_longest_divergence_key_hash(state);
            DiffDetectionState::HashDiffDetected
        }
        true => DiffDetectionState::NoDiffDetected,
    }
}

/// If the node type contains a value (without looking at the children), then
/// return it.
const fn get_value_from_node<T: PartialTrie>(n: &Node<T>) -> Option<&Vec<u8>> {
    match n {
        Node::Empty | Node::Hash(_) | Node::Extension { .. } => None,
        Node::Branch { value, .. } | Node::Leaf { nibbles: _, value } => Some(value),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethereum_types::BigEndianHash;
    use rlp_derive::{RlpDecodable, RlpEncodable};

    use super::create_full_diff_between_tries;
    use crate::{
        debug_tools::diff::{DiffPoint, NodeInfo},
        nibbles::Nibbles,
        partial_trie::{HashedPartialTrie, PartialTrie},
        trie_ops::TrieOpResult,
        utils::{TrieNodeType, TriePath},
    };

    #[test]
    fn depth_single_node_hash_diffs_work() -> TrieOpResult<()> {
        let mut a = HashedPartialTrie::default();
        a.insert(0x1234, vec![0])?;
        let a_hash = a.hash();

        let mut b = a.clone();
        b.insert(0x1234, vec![1])?;
        let b_hash = b.hash();

        let diff = create_full_diff_between_tries(&a, &b);

        let expected_a = NodeInfo {
            key: 0x1234.into(),
            value: Some(vec![0]),
            node_type: TrieNodeType::Leaf,
            hash: a_hash,
        };

        let expected_b = NodeInfo {
            key: 0x1234.into(),
            value: Some(vec![1]),
            node_type: TrieNodeType::Leaf,
            hash: b_hash,
        };

        let expected = DiffPoint {
            depth: 0,
            path: TriePath(vec![]),
            key: Nibbles::default(),
            a_info: expected_a,
            b_info: expected_b,
        };

        assert_eq!(diff.diff_points[0], expected);
        Ok(())
    }

    #[test]
    fn depth_multi_node_diff_works() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use ethereum_types::{H256, U256};
        use keccak_hash::keccak;
        #[derive(
            RlpEncodable, RlpDecodable, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord,
        )]
        pub struct TestAccountRlp {
            pub nonce: U256,
            pub balance: U256,
            pub storage_root: H256,
            pub code_hash: H256,
        }

        let mut data = vec![
            (
                keccak(hex::decode("f0d4c12a5768d806021f80a262b4d39d26c58b8d").unwrap()),
                TestAccountRlp {
                    nonce: U256::from(1),
                    balance: U256::from(2),
                    storage_root: H256::from_uint(&1312378.into()),
                    code_hash: H256::from_uint(&943221.into()),
                },
            ),
            (
                keccak(hex::decode("95222290dd7278aa3ddd389cc1e1d165cc4bafe5").unwrap()),
                TestAccountRlp {
                    nonce: U256::from(2),
                    balance: U256::from(3),
                    storage_root: H256::from_uint(&1123178.into()),
                    code_hash: H256::from_uint(&8133221.into()),
                },
            ),
            (
                keccak(hex::decode("43682bcf1ce452a70b72c109551084076c6377e0").unwrap()),
                TestAccountRlp {
                    nonce: U256::from(100),
                    balance: U256::from(101),
                    storage_root: H256::from_uint(&12345678.into()),
                    code_hash: H256::from_uint(&94321.into()),
                },
            ),
            (
                keccak(hex::decode("97a9a15168c22b3c137e6381037e1499c8ad0978").unwrap()),
                TestAccountRlp {
                    nonce: U256::from(3000),
                    balance: U256::from(3002),
                    storage_root: H256::from_uint(&123456781.into()),
                    code_hash: H256::from_uint(&943214141.into()),
                },
            ),
        ];

        let create_trie_with_data = |trie: &Vec<(H256, TestAccountRlp)>| -> Result<HashedPartialTrie, Box<dyn std::error::Error>> {
            let mut tr = HashedPartialTrie::default();
            tr.insert::<Nibbles, &[u8]>(Nibbles::from_str(&hex::encode(trie[0].0.as_bytes()))?, rlp::encode(&trie[0].1).as_ref())?;
            tr.insert::<Nibbles, &[u8]>(Nibbles::from_str(&hex::encode(trie[1].0.as_bytes()))?, rlp::encode(&trie[1].1).as_ref())?;
            tr.insert::<Nibbles, &[u8]>(Nibbles::from_str(&hex::encode(trie[2].0.as_bytes()))?, rlp::encode(&trie[2].1).as_ref())?;
            tr.insert::<Nibbles, &[u8]>(Nibbles::from_str(&hex::encode(trie[3].0.as_bytes()))?, rlp::encode(&trie[3].1).as_ref())?;
            Ok(tr)
        };

        let a = create_trie_with_data(&data)?;

        // Change data on multiple accounts
        data[1].1.balance += U256::from(1);
        data[3].1.nonce += U256::from(2);
        data[3].1.storage_root = H256::from_uint(&4445556.into());
        let b = create_trie_with_data(&data)?;

        let diff = create_full_diff_between_tries(&a, &b);

        assert_eq!(diff.diff_points.len(), 2);
        assert_eq!(&diff.diff_points[0].key.to_string(), "0x3");
        assert_eq!(&diff.diff_points[1].key.to_string(), "0x55");

        Ok(())
    }

    // TODO: Will finish these tests later (low-priority).
    #[test]
    #[ignore]
    fn depth_multi_node_single_node_hash_diffs_work() {
        todo!()
    }

    #[test]
    #[ignore]
    fn depth_multi_node_single_node_node_diffs_work() {
        todo!()
    }

    #[test]
    #[ignore]
    fn depth_massive_single_node_diff_tests() {
        todo!()
    }

    #[test]
    #[ignore]
    fn depth_multi_node_multi_node_hash_diffs_work() {
        todo!()
    }

    #[test]
    #[ignore]
    fn depth_multi_node_multi_node_node_diffs_work() {
        todo!()
    }

    #[test]
    #[ignore]
    fn depth_massive_multi_node_diff_tests() {
        todo!()
    }
}
