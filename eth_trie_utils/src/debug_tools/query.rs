use std::fmt::{self, Display};

use super::common::{get_segment_from_node_and_key_piece, NodePath, PathSegment};
use crate::{
    nibbles::Nibbles,
    partial_trie::{Node, PartialTrie},
};

#[derive(Clone, Debug)]
pub struct DebugQueryParams {
    include_key_piece_per_node: bool,
    include_node_type: bool,
    // TODO: Look at implementing later...
    // include_node_specific_values: bool,
}

impl Default for DebugQueryParams {
    fn default() -> Self {
        Self {
            include_key_piece_per_node: true,
            include_node_type: true,
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

    pub fn build(self) -> DebugQueryParams {
        self.params
    }
}

#[derive(Debug)]
pub struct DebugQuery {
    k: Nibbles,
    params: DebugQueryParams,
}

impl From<Nibbles> for DebugQuery {
    fn from(_v: Nibbles) -> Self {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct DebugQueryOutput {
    k: Nibbles,
    node_path: NodePath,
    node_found: bool,
    params: DebugQueryParams,
}

impl Display for DebugQueryOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_query_header(f)?;

        writeln!(f, "Query path:")?;
        for seg in self.node_path.0.iter().take(self.node_path.0.len() - 1) {
            Self::fmt_node_based_on_debug_params(f, seg, &self.params)?;
            writeln!(f)?;
            writeln!(f, "V")?;
        }

        if let Some(last_seg) = self.node_path.0.last() {
            Self::fmt_node_based_on_debug_params(f, last_seg, &self.params)?;
        }

        Ok(())
    }
}

impl DebugQueryOutput {
    fn new(k: Nibbles, params: DebugQueryParams) -> Self {
        Self {
            k,
            node_path: NodePath::default(),
            node_found: false,
            params,
        }
    }

    fn fmt_query_header(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Query Result {{")?;

        writeln!(f, "Queried Key: {}", self.k)?;
        writeln!(f, "Node node: {}", self.node_found)?;

        writeln!(f, "}}")
    }

    fn fmt_node_based_on_debug_params(
        f: &mut fmt::Formatter<'_>,
        seg: &PathSegment,
        params: &DebugQueryParams,
    ) -> fmt::Result {
        let node_type = seg.node_type();

        if params.include_node_type {
            write!(f, "{}", node_type)?;
        }

        write!(f, "(")?;

        if params.include_key_piece_per_node {
            if let Some(k_piece) = seg.get_key_piece_from_seg_if_present() {
                write!(f, "key: {} ", k_piece)?;
            }
        }

        write!(f, ")")?;

        Ok(())
    }
}

pub fn get_path_from_query<T: PartialTrie>(trie: &Node<T>, q: DebugQuery) -> DebugQueryOutput {
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
