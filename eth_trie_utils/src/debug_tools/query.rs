use std::fmt::{self, Display};

use ethereum_types::H256;

use super::common::{get_segment_from_node_and_key_piece, NodePath, PathSegment};
use crate::{
    nibbles::Nibbles,
    partial_trie::{Node, PartialTrie, WrappedNode},
};

#[derive(Clone, Debug)]
pub struct DebugQueryParams {
    include_key_piece_per_node: bool,
    include_node_type: bool,
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

    // I think the clippy lint actually makes it a lot less readable in this case.
    #[allow(clippy::needless_range_loop)]
    for i in 0..16 {
        if !matches!(children[i].as_ref(), Node::Empty) {
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

    fn fmt_query_header(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Query Result {{")?;

        writeln!(f, "Queried Key: {}", self.k)?;
        writeln!(f, "Node found: {}", self.node_found)?;

        writeln!(f, "}}")
    }

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
    let seg = get_segment_from_node_and_key_piece(node, curr_key);
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
            curr_key.pop_nibbles_front(nibbles.count);
            get_path_from_query_rec(child, curr_key, query_out);
        }
        Node::Leaf { nibbles, value: _ } => {
            curr_key.pop_nibbles_front(nibbles.count);
        }
    }

    if curr_key.is_empty() {
        query_out.node_found = true;
    }
}
