//! Defines various operations for
//! [`PartialTrie`].

use std::{array, fmt::Display, mem::size_of};

use enum_as_inner::EnumAsInner;
use ethereum_types::{H256, U128, U256, U512};
use log::trace;
use thiserror::Error;

use crate::{
    nibbles::{Nibble, Nibbles},
    partial_trie::Node,
    utils::NodeKind,
};

/// Stores the result of trie operations. Returns a [TrieOpError] upon
/// failure.
pub type TrieOpResult<T> = Result<T, TrieOpError>;

/// An error type for trie operation.
#[derive(Clone, Debug, Error)]
pub enum TrieOpError {
    /// An error that occurs when a hash node is found during an insert
    /// operation.
    #[error("Found a `Hash` node during an insert in a `PartialTrie`! These should not be able to be traversed during an insert! (hash: {0})")]
    HashNodeInsertError(H256),

    /// An error that occurs when a hash node is found during a delete
    /// operation.
    #[error("Attempted to delete a value that ended up inside a hash node! (hash: {0})")]
    HashNodeDeleteError(H256),

    /// An error that occurs when encontered an unexisting type of node during
    /// an extension node collapse.
    #[error("Extension managed to get an unexisting child node type! (child: {0})")]
    HashNodeExtError(NodeKind),

    /// Failed to insert a hash node into the trie.
    #[error("Attempted to place a hash node on an existing node! (hash: {0})")]
    ExistingHashNodeError(H256),
}

/// A entry to be inserted into a `PartialTrie`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct InsertEntry {
    pub nibbles: Nibbles,
    pub v: ValOrHash,
}

impl From<(Nibbles, ValOrHash)> for InsertEntry {
    fn from((nibbles, v): (Nibbles, ValOrHash)) -> Self {
        Self { nibbles, v }
    }
}

impl Display for InsertEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TrieEntry: (k: {}, v: {:?})", &self.nibbles, self.v)
    }
}

impl InsertEntry {
    pub(crate) fn truncate_n_nibbles(&mut self, n: usize) {
        self.nibbles = self.nibbles.truncate_n_nibbles_front(n);
    }
}

/// An "entry" in a [`PartialTrie`].
///
/// Entries in the trie may either be actual values or
/// [`Hash`](crate::partial_trie::Node::Hash) nodes.
#[derive(Clone, Debug, EnumAsInner, Eq, Hash, PartialEq)]
pub enum ValOrHash {
    /// A value in a trie.
    Val(Vec<u8>),

    /// A part of a larger trie that we are not storing but still need to know
    /// the merkle hash for.
    Hash(H256),
}

macro_rules! impl_eth_type_from_for_val_variant {
    ($type:ty) => {
        impl From<$type> for ValOrHash {
            fn from(v: $type) -> Self {
                let size = size_of::<Self>();

                let mut buf = Vec::with_capacity(size);
                buf.resize(32, 0);
                v.to_big_endian(&mut buf);
                ValOrHash::Val(buf)
            }
        }
    };
}

macro_rules! impl_prim_int_from_for_val_variant {
    ($type:ty) => {
        impl From<$type> for ValOrHash {
            fn from(v: $type) -> Self {
                let buf = v.to_be_bytes();
                ValOrHash::Val(buf.into())
            }
        }
    };
}

impl From<Vec<u8>> for ValOrHash {
    fn from(value: Vec<u8>) -> Self {
        Self::Val(value)
    }
}

impl From<&[u8]> for ValOrHash {
    fn from(value: &[u8]) -> Self {
        Self::Val(value.to_vec())
    }
}

impl From<H256> for ValOrHash {
    fn from(hash: H256) -> Self {
        Self::Hash(hash)
    }
}

impl_eth_type_from_for_val_variant!(U512);
impl_eth_type_from_for_val_variant!(U256);
impl_eth_type_from_for_val_variant!(U128);
impl_prim_int_from_for_val_variant!(u64);
impl_prim_int_from_for_val_variant!(u32);
impl_prim_int_from_for_val_variant!(u16);
impl_prim_int_from_for_val_variant!(u8);

impl ValOrHash {
    /// Cast a [`ValOrHash::Hash`] enum to the hash ([`H256`]). Panics if called
    /// on the wrong enum variant.
    pub fn expect_hash(self) -> H256 {
        self.into_hash()
            .expect("Expected a `ValOrHash` to be a hash")
    }

    /// Cast a [`ValOrHash::Val`] enum to the value ([`Vec<u8>`]). Panics if
    /// called on the wrong enum variant.
    pub fn expect_val(self) -> Vec<u8> {
        self.into_val()
            .expect("Expected a `ValOrHash` to be a value")
    }
}

/// prefix/postfix info when comparing two `Nibbles`.
#[derive(Debug)]
struct ExistingAndNewNodePreAndPost {
    common_prefix: Nibbles,
    existing_postfix: Nibbles,
    new_postfix: Nibbles,
}

/// When splitting a leaf/extension node after an insert, there is a chance that
/// we may place one of the nodes right into the value node of the branch. This
/// enum just indicates whether or not a value needs to go into the branch node.
#[derive(Debug)]
enum ExistingOrNewBranchValuePlacement {
    BranchValue(Vec<u8>, (Nibble, Node)),
    BothBranchChildren((Nibble, Node), (Nibble, Node)),
}

#[derive(Debug)]
enum IterStackEntry {
    Root(Node),
    Extension(usize),
    Branch(BranchStackEntry),
}

#[derive(Debug)]
struct BranchStackEntry {
    children: [Box<Node>; 16],
    value: Vec<u8>,
    curr_nib: Nibble,
}

#[derive(Debug)]
/// An iterator that ranges over all the leafs and hash nodes
/// of the trie, in lexicographic order.
pub struct PartialTrieIter {
    curr_key_after_last_branch: Nibbles,
    trie_stack: Vec<IterStackEntry>,
}

impl PartialTrieIter {
    fn advance_iter_to_next_empty_leaf_or_hash_node(
        &mut self,
        node: &Node,
        mut curr_key: Nibbles,
    ) -> Option<(Nibbles, ValOrHash)> {
        match node {
            Node::Empty => None,
            Node::Hash(h) => Some((curr_key, ValOrHash::Hash(*h))),
            Node::Branch { children, value } => {
                self.trie_stack
                    .push(IterStackEntry::Branch(BranchStackEntry {
                        children: children.clone(),
                        value: value.clone(),
                        curr_nib: 1,
                    }));

                self.curr_key_after_last_branch = curr_key;
                curr_key.push_nibble_back(0);
                self.advance_iter_to_next_empty_leaf_or_hash_node(&children[0], curr_key)
            }
            Node::Extension { nibbles, child } => {
                if NodeKind::of(child) != NodeKind::Hash {
                    self.trie_stack
                        .push(IterStackEntry::Extension(nibbles.count));
                }

                curr_key = curr_key.merge_nibbles(nibbles);

                self.advance_iter_to_next_empty_leaf_or_hash_node(child, curr_key)
            }
            Node::Leaf { nibbles, value } => {
                curr_key = curr_key.merge_nibbles(nibbles);
                Some((curr_key, ValOrHash::Val(value.clone())))
            }
        }
    }
}

impl Iterator for PartialTrieIter {
    type Item = (Nibbles, ValOrHash);

    fn next(&mut self) -> Option<(Nibbles, ValOrHash)> {
        let mut next_iter_item = None;

        while next_iter_item.is_none() {
            let mut stack_entry = match self.trie_stack.pop() {
                Some(e) => e,
                None => break,
            };

            next_iter_item = match stack_entry {
                IterStackEntry::Root(root) => {
                    self.advance_iter_to_next_empty_leaf_or_hash_node(&root, Nibbles::default())
                }
                IterStackEntry::Extension(num_nibbles) => {
                    // Drop nibbles that extension added since we are going back up the trie.
                    self.curr_key_after_last_branch
                        .truncate_n_nibbles_back_mut(num_nibbles);
                    None
                }
                IterStackEntry::Branch(ref mut branch_entry) => {
                    let curr_nib = branch_entry.curr_nib;

                    match curr_nib {
                        1..=15 => {
                            branch_entry.curr_nib += 1;
                            let next_child = branch_entry.children[curr_nib as usize].clone();
                            self.trie_stack.push(stack_entry);

                            let updated_key =
                                self.curr_key_after_last_branch.merge_nibble(curr_nib);
                            self.advance_iter_to_next_empty_leaf_or_hash_node(
                                &next_child,
                                updated_key,
                            )
                        }
                        16 => {
                            let res = match branch_entry.value.is_empty() {
                                false => {
                                    let value_key = self.curr_key_after_last_branch;
                                    Some((value_key, ValOrHash::Val(branch_entry.value.clone())))
                                }
                                true => None,
                            };

                            if !self.curr_key_after_last_branch.is_empty() {
                                self.curr_key_after_last_branch
                                    .truncate_n_nibbles_back_mut(1);
                            }

                            res
                        }
                        _ => unreachable!("Trie iterator managed to reach nibble 17 or 0"),
                    }
                }
            }
        }

        next_iter_item
    }
}

impl Node {
    pub(crate) fn trie_insert<K, V>(&mut self, k: K, v: V) -> TrieOpResult<()>
    where
        K: Into<Nibbles>,
        V: Into<ValOrHash>,
    {
        let ins_entry = (k.into(), v.into()).into();
        trace!("Inserting new node {:?}...", ins_entry);

        // Inserts are guaranteed to update the root node.
        let node_ref: &Node = &insert_into_trie_rec(self, ins_entry)?.unwrap();
        *self = node_ref.clone();
        Ok(())
    }

    pub(crate) fn trie_extend<K, V, I>(&mut self, nodes: I) -> TrieOpResult<()>
    where
        K: Into<Nibbles>,
        V: Into<ValOrHash>,
        I: IntoIterator<Item = (K, V)>,
    {
        for (k, v) in nodes {
            self.trie_insert(k, v)?;
        }
        Ok(())
    }

    pub(crate) fn trie_get<K>(&self, k: K) -> Option<&[u8]>
    where
        K: Into<Nibbles>,
    {
        self.trie_get_intern(&mut k.into())
    }

    fn trie_get_intern(&self, curr_nibbles: &mut Nibbles) -> Option<&[u8]> {
        match self {
            Node::Empty | Node::Hash(_) => {
                trace!("Get traversed {:?}", self);
                None
            }
            // Note: If we end up supporting non-fixed sized keys, then we need to also check value.
            Node::Branch { children, value } => {
                // Check against branch value.
                if curr_nibbles.is_empty() {
                    return (!value.is_empty()).then_some(value.as_slice());
                }

                let nib = curr_nibbles.pop_next_nibble_front();
                trace!("Get traversed Branch (nibble: {:x})", nib);
                children[nib as usize].trie_get_intern(curr_nibbles)
            }
            Node::Extension { nibbles, child } => {
                trace!("Get traversed Extension (nibbles: {:?})", nibbles);
                let r = curr_nibbles.pop_nibbles_front(nibbles.count);

                match r.nibbles_are_identical_up_to_smallest_count(nibbles) {
                    false => None,
                    true => child.trie_get_intern(curr_nibbles),
                }
            }
            Node::Leaf { nibbles, value } => {
                trace!("Get traversed Leaf (nibbles: {:?})", nibbles);
                match nibbles.nibbles_are_identical_up_to_smallest_count(curr_nibbles) {
                    false => None,
                    true => Some(value),
                }
            }
        }
    }

    pub(crate) fn trie_delete<K>(&mut self, k: K) -> TrieOpResult<Option<Vec<u8>>>
    where
        K: Into<Nibbles>,
    {
        let k: Nibbles = k.into();
        trace!("Deleting a leaf node with key {} if it exists", k);

        delete_intern(&self.clone(), k)?.map_or(Ok(None), |(updated_root, deleted_val)| {
            // Final check at the root if we have an extension node
            let wrapped_node = try_collapse_if_extension(updated_root)?;
            let node_ref: &Node = &wrapped_node;
            *self = node_ref.clone();

            Ok(Some(deleted_val))
        })
    }

    pub(crate) fn trie_items(&self) -> impl Iterator<Item = (Nibbles, ValOrHash)> {
        PartialTrieIter {
            curr_key_after_last_branch: Nibbles::default(),
            trie_stack: vec![IterStackEntry::Root(self.clone())],
        }
    }

    pub(crate) fn trie_keys(&self) -> impl Iterator<Item = Nibbles> {
        self.trie_items().map(|(k, _)| k)
    }

    pub(crate) fn trie_values(&self) -> impl Iterator<Item = ValOrHash> {
        self.trie_items().map(|(_, v)| v)
    }

    pub(crate) fn trie_has_item_by_key<K>(&self, k: K) -> bool
    where
        K: Into<Nibbles>,
    {
        let k = k.into();
        self.trie_items().any(|(key, _)| key == k)
    }
}

fn insert_into_trie_rec(node: &Node, mut new_node: InsertEntry) -> TrieOpResult<Option<Node>> {
    match node {
        Node::Empty => {
            trace!("Insert traversed Empty");
            Ok(Some(create_node_from_insert_val(
                new_node.nibbles,
                new_node.v,
            )))
        }
        Node::Hash(h) => {
            trace!("Insert traversed {:?}", node);
            Err(TrieOpError::HashNodeInsertError(*h))
        }
        Node::Branch { children, value } => {
            if new_node.nibbles.count == 0 {
                trace!("Insert traversed branch and placed value in node");
                return Ok(Some(branch_from_insert_val(children.clone(), new_node.v)?));
            }

            let nibble = new_node.nibbles.pop_next_nibble_front();
            trace!("Insert traversed Branch (nibble: {:x})", nibble);

            Ok(
                insert_into_trie_rec(&children[nibble as usize], new_node)?.map(|updated_child| {
                    let mut updated_children = children.clone();
                    updated_children[nibble as usize] = Box::new(updated_child);
                    branch(updated_children, value.clone())
                }),
            )
        }
        Node::Extension { nibbles, child } => {
            trace!("Insert traversed Extension (nibbles: {:?})", nibbles);

            // Note: Child is guaranteed to be either a `Branch` or a `Hash` node.

            let info = get_pre_and_postfixes_for_existing_and_new_nodes(nibbles, &new_node.nibbles);

            if nibbles.nibbles_are_identical_up_to_smallest_count(&new_node.nibbles) {
                new_node.truncate_n_nibbles(nibbles.count);

                return insert_into_trie_rec(child, new_node)?.map_or(Ok(None), |updated_child| {
                    Ok(Some(extension(*nibbles, Box::new(updated_child))))
                });
            }

            // Drop one since branch will cover one nibble.
            // Also note that the postfix is always >= 1.
            let existing_postfix_adjusted_for_branch =
                info.existing_postfix.truncate_n_nibbles_front(1);

            // If we split an extension node, we may need to place an extension node after
            // the branch.
            let updated_existing_node = match existing_postfix_adjusted_for_branch.count {
                0 => *child.clone(),
                _ => extension(existing_postfix_adjusted_for_branch, child.clone()),
            };

            Ok(Some(place_branch_and_potentially_ext_prefix(
                &info,
                updated_existing_node,
                new_node,
            )))
        }
        Node::Leaf { nibbles, value } => {
            trace!("Insert traversed Leaf (nibbles: {:?})", nibbles);

            // Update existing node value if already present.
            if *nibbles == new_node.nibbles {
                return Ok(Some(leaf_from_insert_val(*nibbles, new_node.v)?));
            }

            let info = get_pre_and_postfixes_for_existing_and_new_nodes(nibbles, &new_node.nibbles);

            // This existing leaf is going in a branch, so we need to truncate the first
            // nibble since it's going to be represented by the branch.
            let existing_node_truncated = leaf(
                nibbles.truncate_n_nibbles_front(info.common_prefix.count + 1),
                value.clone(),
            );

            Ok(Some(place_branch_and_potentially_ext_prefix(
                &info,
                existing_node_truncated,
                new_node,
            )))
        }
    }
}

fn delete_intern(node: &Node, mut curr_k: Nibbles) -> TrieOpResult<Option<(Node, Vec<u8>)>> {
    match node {
        Node::Empty => {
            trace!("Delete traversed Empty");
            Ok(None)
        }
        Node::Hash(h) => Err(TrieOpError::HashNodeDeleteError(*h)),
        // TODO: Find a nice way to get the full key path...
        Node::Branch { children, value } => {
            if curr_k.is_empty() {
                return Ok(Some((branch(children.clone(), Vec::new()), value.clone())));
            }

            let nibble = curr_k.pop_next_nibble_front();
            trace!("Delete traversed Branch nibble {:x}", nibble);

            delete_intern(&children[nibble as usize], curr_k)?.map_or(Ok(None),
                |(updated_child, value_deleted)| {
                    // If the child we recursively called is deleted, then we may need to reduce
                    // this branch to an extension/leaf.
                    let updated_node = match node_is_empty(&updated_child)
                        && get_num_non_empty_children(children) <= 2
                    {
                        false => {
                            // Branch stays.
                            let mut updated_children = children.clone();
                            updated_children[nibble as usize] =
                                Box::new(try_collapse_if_extension(updated_child)?);
                            branch(updated_children, value.clone())
                        }
                        true => {
                            let (child_nibble, non_empty_node) =
                                get_other_non_empty_child_and_nibble_in_two_elem_branch(
                                    children, nibble,
                                );

                            trace!("Branch {:x} became an extension when collapsing a branch (may be collapsed further still).
                                Single remaining child in slot {:x} ({}) will be pointed at with an extension node.",
                                nibble, child_nibble, NodeKind::of(non_empty_node));

                            // Extension may be collapsed one level above.
                            extension(Nibbles::from_nibble(child_nibble), non_empty_node.clone())
                        }
                    };

                    Ok(Some((updated_node, value_deleted)))
                },
            )
        }
        Node::Extension {
            nibbles: ext_nibbles,
            child,
        } => {
            trace!("Delete traversed Extension (nibbles: {:?})", ext_nibbles);

            ext_nibbles
                .nibbles_are_identical_up_to_smallest_count(&curr_k)
                .then(|| {
                    curr_k.truncate_n_nibbles_front_mut(ext_nibbles.count);

                    delete_intern(child, curr_k).and_then(|res| {
                        res.map_or(Ok(None), |(updated_child, value_deleted)| {
                            let updated_node =
                                collapse_ext_node_if_needed(ext_nibbles, &updated_child)?;
                            Ok(Some((updated_node, value_deleted)))
                        })
                    })
                })
                .unwrap_or(Ok(None))
        }
        Node::Leaf { nibbles, value } => {
            trace!("Delete traversed Leaf (nibbles: {:?})", nibbles);
            Ok((*nibbles == curr_k).then(|| {
                trace!("Deleting leaf ({:x})", nibbles);
                (Node::Empty, value.clone())
            }))
        }
    }
}

fn try_collapse_if_extension(node: Node) -> TrieOpResult<Node> {
    match &node {
        Node::Extension { nibbles, child } => collapse_ext_node_if_needed(nibbles, child),
        _ => Ok(node),
    }
}

fn collapse_ext_node_if_needed(ext_nibbles: &Nibbles, child: &Node) -> TrieOpResult<Node> {
    trace!(
        "Collapsing extension node ({:x}) with child {}...",
        ext_nibbles,
        NodeKind::of(child)
    );

    match child {
        Node::Branch { .. } => Ok(extension(*ext_nibbles, child.clone())),
        Node::Extension {
            nibbles: other_ext_nibbles,
            child: other_ext_child,
        } => Ok(extension(
            ext_nibbles.merge_nibbles(other_ext_nibbles),
            other_ext_child.clone(),
        )),
        Node::Leaf {
            nibbles: leaf_nibbles,
            value,
        } => Ok(leaf(ext_nibbles.merge_nibbles(leaf_nibbles), value.clone())),
        Node::Hash(_) => Ok(extension(*ext_nibbles, child.clone())),
        _ => Err(TrieOpError::HashNodeExtError(NodeKind::of(child))),
    }
}

fn get_pre_and_postfixes_for_existing_and_new_nodes(
    existing_node_nibbles: &Nibbles,
    new_node_nibbles: &Nibbles,
) -> ExistingAndNewNodePreAndPost {
    let nib_idx_of_difference =
        Nibbles::find_nibble_idx_that_differs_between_nibbles_different_lengths(
            existing_node_nibbles,
            new_node_nibbles,
        );

    let (common_prefix, existing_postfix) =
        existing_node_nibbles.split_at_idx(nib_idx_of_difference);
    let new_postfix = new_node_nibbles.split_at_idx_postfix(nib_idx_of_difference);

    ExistingAndNewNodePreAndPost {
        common_prefix,
        existing_postfix,
        new_postfix,
    }
}

fn place_branch_and_potentially_ext_prefix(
    info: &ExistingAndNewNodePreAndPost,
    existing_node: Node,
    new_node: InsertEntry,
) -> Node {
    let mut children = new_branch_child_arr();
    let mut value = vec![];

    match check_if_existing_or_new_node_should_go_in_branch_value_field(
        info,
        existing_node,
        new_node,
    ) {
        ExistingOrNewBranchValuePlacement::BranchValue(branch_v, (nib, node)) => {
            children[nib as usize] = Box::new(node);
            value = branch_v;
        }
        ExistingOrNewBranchValuePlacement::BothBranchChildren((nib_1, node_1), (nib_2, node_2)) => {
            children[nib_1 as usize] = Box::new(node_1);
            children[nib_2 as usize] = Box::new(node_2);
        }
    }

    let branch = branch(children, value);

    match info.common_prefix.count {
        0 => branch,
        _ => extension(info.common_prefix, branch),
    }
}

/// Check if the new leaf or existing node (either leaf/extension) should go
/// into the value field of the new branch.
fn check_if_existing_or_new_node_should_go_in_branch_value_field(
    info: &ExistingAndNewNodePreAndPost,
    existing_node: Node,
    new_node_entry: InsertEntry,
) -> ExistingOrNewBranchValuePlacement {
    // Guaranteed that both postfixes are not equal at this point.
    match (
        info.existing_postfix.count,
        info.new_postfix.count,
        &existing_node,
    ) {
        (0, _, Node::Leaf { value, .. }) => ExistingOrNewBranchValuePlacement::BranchValue(
            value.clone(),
            ins_entry_into_leaf_and_nibble(info, new_node_entry),
        ),

        (_, 0, _) => ExistingOrNewBranchValuePlacement::BranchValue(
            new_node_entry.v.expect_val(),
            (info.existing_postfix.get_nibble(0), existing_node.clone()),
        ),
        (_, _, _) => ExistingOrNewBranchValuePlacement::BothBranchChildren(
            (info.existing_postfix.get_nibble(0), existing_node.clone()),
            ins_entry_into_leaf_and_nibble(info, new_node_entry),
        ),
    }
}

fn ins_entry_into_leaf_and_nibble(
    info: &ExistingAndNewNodePreAndPost,
    entry: InsertEntry,
) -> (Nibble, Node) {
    let new_first_nibble = info.new_postfix.get_nibble(0);
    let new_node = create_node_from_insert_val(
        entry
            .nibbles
            .truncate_n_nibbles_front(info.common_prefix.count + 1),
        entry.v,
    );

    (new_first_nibble, new_node)
}

fn new_branch_child_arr() -> [Box<Node>; 16] {
    array::from_fn(|_ix| Box::new(Node::Empty))
}

fn get_num_non_empty_children(children: &[Box<Node>; 16]) -> usize {
    children.iter().filter(|c| !node_is_empty(c)).count()
}

fn get_other_non_empty_child_and_nibble_in_two_elem_branch(
    children: &[Box<Node>; 16],
    our_nib: Nibble,
) -> (Nibble, &Node) {
    children
        .iter()
        .enumerate()
        .find(|(i, c)| *i != our_nib as usize && !node_is_empty(c))
        .map(|(n, c)| (n as Nibble, &**c))
        .expect("Expected to find a non-empty node in the branch's children")
}

fn node_is_empty(node: &Node) -> bool {
    matches!(node, Node::Empty)
}

pub(crate) fn branch(children: [Box<Node>; 16], value: Vec<u8>) -> Node {
    Node::Branch { children, value }
}

fn branch_from_insert_val(children: [Box<Node>; 16], value: ValOrHash) -> TrieOpResult<Node> {
    create_node_if_ins_val_not_hash(value, |value| Node::Branch { children, value })
}

fn extension(nibbles: Nibbles, child: impl Into<Box<Node>>) -> Node {
    Node::Extension {
        nibbles,
        child: child.into(),
    }
}

fn leaf(nibbles: Nibbles, value: Vec<u8>) -> Node {
    Node::Leaf { nibbles, value }
}

fn leaf_from_insert_val(nibbles: Nibbles, value: ValOrHash) -> TrieOpResult<Node> {
    create_node_if_ins_val_not_hash(value, |value| Node::Leaf { nibbles, value })
}

fn create_node_from_insert_val(nibbles: Nibbles, value: ValOrHash) -> Node {
    match value {
        ValOrHash::Val(value) => Node::Leaf { nibbles, value },
        ValOrHash::Hash(h) => {
            let hash_node = Node::Hash(h);

            match nibbles.is_empty() {
                // Since hash nodes can represent remaining nibbles like leaves can, we must insert
                // an extension node in this case.
                false => Node::Extension {
                    nibbles,
                    child: hash_node.into(),
                },
                true => hash_node,
            }
        }
    }
}

fn create_node_if_ins_val_not_hash<F: FnOnce(Vec<u8>) -> Node>(
    value: ValOrHash,
    create_node_f: F,
) -> TrieOpResult<Node> {
    match value {
        ValOrHash::Val(leaf_v) => Ok(create_node_f(leaf_v)),
        ValOrHash::Hash(h) => Err(TrieOpError::ExistingHashNodeError(h)),
    }
}
