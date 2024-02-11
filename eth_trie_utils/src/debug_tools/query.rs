//! Query tooling to report info on the path taken when searching down a trie
//! with a given key.

use std::fmt::{self, Display};

use ethereum_types::H256;

use super::common::{
    get_key_piece_from_node_pulling_from_key_for_branches, get_segment_from_node_and_key_piece,
    NodePath, PathSegment,
};
use crate::{
    nibbles::Nibbles,
    partial_trie::{Node, PartialTrie, WrappedNode},
};

/// Params controlling how much information is reported in the query output.
///
/// By default, the node type along with its key piece is printed out per node
/// (eg. "Leaf(0x1234)"). Additional node specific information can be printed
/// out by enabling `include_node_specific_values`.
#[derive(Clone, Debug)]
pub struct DebugQueryParams {
    /// Include (if applicable) the piece of the key that is contained by the
    /// node (eg. ("0x1234")).
    include_key_piece_per_node: bool,

    /// Include the type of node (eg "Branch").
    include_node_type: bool,

    /// Include additional data that is specific to the node type (eg. The mask
    /// of a `Branch` or the hash of a `Hash` node).
    include_node_specific_values: bool,
}

impl Default for DebugQueryParams {
    fn default() -> Self {
        Self {
            include_key_piece_per_node: true,
            include_node_type: true,
            include_node_specific_values: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct DebugQueryParamsBuilder {
    params: DebugQueryParams,
}

impl DebugQueryParamsBuilder {
    /// Defaults to `true`.
    pub fn print_key_pieces(mut self, enabled: bool) -> Self {
        self.params.include_key_piece_per_node = enabled;
        self
    }

    /// Defaults to `true`.
    pub fn print_node_type(mut self, enabled: bool) -> Self {
        self.params.include_node_type = enabled;
        self
    }

    /// Defaults to `false`.
    pub fn print_node_specific_values(mut self, enabled: bool) -> Self {
        self.params.include_node_specific_values = enabled;
        self
    }

    pub fn build<K: Into<Nibbles>>(self, k: K) -> DebugQuery {
        DebugQuery {
            k: k.into(),
            params: self.params,
        }
    }
}

/// The payload to give to the query function. Construct this from the builder.
#[derive(Debug)]
pub struct DebugQuery {
    k: Nibbles,
    params: DebugQueryParams,
}

impl From<Nibbles> for DebugQuery {
    fn from(k: Nibbles) -> Self {
        Self {
            k,
            params: DebugQueryParams::default(),
        }
    }
}

/// Extra data that is associated with a node. Only used if
/// `include_node_specific_values` is `true`.
#[derive(Clone, Debug)]
enum ExtraNodeSegmentInfo {
    Hash(H256),
    Branch { child_mask: u16 },
    Leaf { value: Vec<u8> },
}

impl Display for ExtraNodeSegmentInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtraNodeSegmentInfo::Hash(h) => write!(f, "Hash: {:x}", h),
            ExtraNodeSegmentInfo::Branch { child_mask } => write!(
                f,
                "mask: {:#018b} (Num Children: {})",
                child_mask,
                count_non_empty_branch_children_from_mask(*child_mask)
            ),
            ExtraNodeSegmentInfo::Leaf { value } => write!(f, "Leaf Value: {}", hex::encode(value)),
        }
    }
}

impl ExtraNodeSegmentInfo {
    pub(super) fn from_node<T: PartialTrie>(n: &Node<T>) -> Option<Self> {
        match n {
            Node::Empty | Node::Extension { .. } => None,
            Node::Hash(h) => Some(ExtraNodeSegmentInfo::Hash(*h)),
            Node::Branch { children, .. } => Some(ExtraNodeSegmentInfo::Branch {
                child_mask: create_child_mask_from_children(children),
            }),
            Node::Leaf { value, .. } => Some(ExtraNodeSegmentInfo::Leaf {
                value: value.clone(),
            }),
        }
    }
}

fn create_child_mask_from_children<T: PartialTrie>(children: &[WrappedNode<T>; 16]) -> u16 {
    let mut mask: u16 = 0;

    for (i, child) in children.iter().enumerate().take(16) {
        if !matches!(child.as_ref(), Node::Empty) {
            mask |= (1 << i) as u16;
        }
    }

    mask
}

fn count_non_empty_branch_children_from_mask(mask: u16) -> usize {
    let mut num_children = 0;

    for i in 0..16 {
        num_children += ((mask & (1 << i)) > 0) as usize;
    }

    num_children
}

#[derive(Clone, Debug)]
pub struct DebugQueryOutput {
    k: Nibbles,
    node_path: NodePath,
    extra_node_info: Vec<Option<ExtraNodeSegmentInfo>>,
    node_found: bool,
    params: DebugQueryParams,
}

impl Display for DebugQueryOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_query_header(f)?;

        writeln!(f, "Query path:")?;
        for (i, seg) in self
            .node_path
            .0
            .iter()
            .take(self.node_path.0.len() - 1)
            .enumerate()
        {
            Self::fmt_node_based_on_debug_params(f, seg, &self.extra_node_info[i], &self.params)?;
            writeln!(f)?;
            writeln!(f, "V")?;
        }

        if let Some(last_seg) = self.node_path.0.last() {
            Self::fmt_node_based_on_debug_params(
                f,
                last_seg,
                &self.extra_node_info[self.node_path.0.len() - 1],
                &self.params,
            )?;
        }

        Ok(())
    }
}

impl DebugQueryOutput {
    fn new(k: Nibbles, params: DebugQueryParams) -> Self {
        Self {
            k,
            node_path: NodePath::default(),
            extra_node_info: Vec::default(),
            node_found: false,
            params,
        }
    }

    // TODO: Make the output easier to read...
    fn fmt_query_header(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Query Result {{")?;

        writeln!(f, "Queried Key: {}", self.k)?;
        writeln!(f, "Node found: {}", self.node_found)?;

        writeln!(f, "}}")
    }

    // TODO: Make the output easier to read...
    fn fmt_node_based_on_debug_params(
        f: &mut fmt::Formatter<'_>,
        seg: &PathSegment,
        extra_seg_info: &Option<ExtraNodeSegmentInfo>,
        params: &DebugQueryParams,
    ) -> fmt::Result {
        let node_type = seg.node_type();

        if params.include_node_type {
            write!(f, "{}", node_type)?;
        }

        write!(f, "(")?;

        if params.include_key_piece_per_node {
            if let Some(k_piece) = seg.get_key_piece_from_seg_if_present() {
                write!(f, "key: {}", k_piece)?;
            }
        }

        if params.include_node_specific_values {
            if let Some(extra_seg_info) = extra_seg_info {
                if params.include_key_piece_per_node {
                    write!(f, ", ")?;
                }

                write!(f, "Extra Seg Info: {}", extra_seg_info)?;
            }
        }

        write!(f, ")")?;

        Ok(())
    }
}

/// Get debug information on the path taken when querying a key in a given trie.
pub fn get_path_from_query<T: PartialTrie, Q: Into<DebugQuery>>(
    trie: &Node<T>,
    q: Q,
) -> DebugQueryOutput {
    let q = q.into();

    let mut out = DebugQueryOutput::new(q.k, q.params);
    get_path_from_query_rec(trie, &mut q.k.clone(), &mut out);

    out
}

fn get_path_from_query_rec<T: PartialTrie>(
    node: &Node<T>,
    curr_key: &mut Nibbles,
    query_out: &mut DebugQueryOutput,
) {
    let key_piece = get_key_piece_from_node_pulling_from_key_for_branches(node, curr_key);
    let seg = get_segment_from_node_and_key_piece(node, &key_piece);

    query_out.node_path.append(seg);
    query_out
        .extra_node_info
        .push(ExtraNodeSegmentInfo::from_node(node));

    match node {
        Node::Empty | Node::Hash(_) => (),
        Node::Branch { children, value: _ } => {
            let nib = curr_key.pop_next_nibble_front();

            get_path_from_query_rec(&children[nib as usize], curr_key, query_out)
        }
        Node::Extension { nibbles, child } => {
            get_next_nibbles_from_node_key_clamped(curr_key, nibbles.count);
            get_path_from_query_rec(child, curr_key, query_out);
        }
        Node::Leaf { nibbles, value: _ } => {
            let curr_key_next_nibs =
                get_next_nibbles_from_node_key_clamped(curr_key, nibbles.count);

            if *nibbles == curr_key_next_nibs {
                curr_key.pop_nibbles_front(curr_key_next_nibs.count);
            }
        }
    }

    if curr_key.is_empty() {
        query_out.node_found = true;
    }
}

/// Gets the next `n` [`Nibbles`] from the key and clamps it in the case of it
/// going out of range.
fn get_next_nibbles_from_node_key_clamped(key: &Nibbles, n_nibs: usize) -> Nibbles {
    let num_nibs_to_get = n_nibs.min(key.count);
    key.get_next_nibbles(num_nibs_to_get)
}

// TODO: Create some simple tests...
#[cfg(test)]
mod tests {}
