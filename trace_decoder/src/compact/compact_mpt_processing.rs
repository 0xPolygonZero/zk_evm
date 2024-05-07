//! Processing for the mpt compact format as specified here: <https://github.com/ledgerwatch/erigon/blob/devel/docs/programmers_guide/witness_formal_spec.md>

use std::{
    collections::HashMap,
    fmt::{self, Debug, Display},
};

use mpt_trie::partial_trie::HashedPartialTrie;

use super::{
    compact_processing_common::{
        process_compact_prestate_common, try_get_node_entry_from_witness_entry, AccountNodeCode,
        Balance, BranchMask, CollapsableWitnessEntryTraverser, CompactCursorFast,
        CompactDecodingResult, CompactParsingError, CompactParsingResult, DebugCompactCursor,
        Header, Instruction, LeafNodeData, NodeEntry, Nonce, ParserState, ProcessedCompactOutput,
        WitnessBytes, WitnessEntry, BRANCH_MAX_CHILDREN,
        MAX_WITNESS_ENTRIES_NEEDED_TO_MATCH_A_RULE,
    },
    compact_to_mpt_trie::{
        create_mpt_trie_from_remaining_witness_elem, create_storage_mpt_trie_from_compact_node,
        StateTrieExtractionOutput,
    },
};
use crate::{trace_protocol::MptTrieCompact, types::HashedAccountAddr};

/// Account node data.
#[derive(Clone, Debug, PartialEq)]
pub struct AccountNodeData {
    /// The nonce of the account.
    pub nonce: Nonce,
    /// The balance of the account.
    pub balance: Balance,
    /// The storage trie of the account.
    pub storage_trie: Option<HashedPartialTrie>,
    /// The code of the account.
    pub account_node_code: Option<AccountNodeCode>,
}

impl AccountNodeData {
    fn new(
        nonce: Nonce,
        balance: Balance,
        storage_trie: Option<HashedPartialTrie>,
        account_node_code: Option<AccountNodeCode>,
    ) -> Self {
        Self {
            nonce,
            balance,
            storage_trie,
            account_node_code,
        }
    }
}

impl ParserState {
    fn create_and_extract_header_mpt(
        witness_bytes_raw: Vec<u8>,
    ) -> CompactParsingResult<(Header, Self)> {
        let witness_bytes = WitnessBytes::<CompactCursorFast>::new(witness_bytes_raw);
        let (header, entries) = witness_bytes.process_into_instructions_and_header()?;

        let p_state = Self { entries };

        Ok((header, p_state))
    }

    // TODO: Move behind a feature flag...
    fn create_and_extract_header_debug_mpt(
        witness_bytes_raw: Vec<u8>,
    ) -> CompactParsingResult<(Header, Self)> {
        let witness_bytes = WitnessBytes::<DebugCompactCursor>::new(witness_bytes_raw);
        let (header, entries) = witness_bytes.process_into_instructions_and_header()?;

        let p_state = Self { entries };

        Ok((header, p_state))
    }

    fn apply_rules_to_witness_entries(
        &mut self,
        entry_buf: &mut Vec<WitnessEntry>,
    ) -> CompactParsingResult<usize> {
        let mut traverser = self.entries.create_collapsable_traverser();

        let mut tot_rules_applied = 0;

        while !traverser.at_end() {
            let num_rules_applied = Self::try_apply_rules_to_curr_entry(&mut traverser, entry_buf)?;
            tot_rules_applied += num_rules_applied;

            if num_rules_applied == 0 {
                // Unable to apply rule at current position, so advance the traverser.
                traverser.advance();
            }
        }

        Ok(tot_rules_applied)
    }

    fn try_apply_rules_to_curr_entry(
        traverser: &mut CollapsableWitnessEntryTraverser,
        buf: &mut Vec<WitnessEntry>,
    ) -> CompactParsingResult<usize> {
        traverser.get_next_n_elems_into_buf(MAX_WITNESS_ENTRIES_NEEDED_TO_MATCH_A_RULE, buf);

        match buf[0].clone() {
            WitnessEntry::Instruction(Instruction::EmptyRoot) => {
                Self::traverser_replace_prev_n_nodes_entry_helper(1, traverser, NodeEntry::Empty)
            }
            WitnessEntry::Instruction(Instruction::Hash(h)) => {
                Self::traverser_replace_prev_n_nodes_entry_helper(1, traverser, NodeEntry::Hash(h))
            }
            WitnessEntry::Instruction(Instruction::Leaf(k, v)) => {
                Self::traverser_replace_prev_n_nodes_entry_helper(
                    1,
                    traverser,
                    NodeEntry::Leaf(k, LeafNodeData::Value(v.into())),
                )
            }
            WitnessEntry::Instruction(Instruction::Extension(k)) => {
                traverser.get_prev_n_elems_into_buf(1, buf);

                match &buf[0] {
                    WitnessEntry::Node(node) => Self::traverser_replace_prev_n_nodes_entry_helper(
                        2,
                        traverser,
                        NodeEntry::Extension(k, Box::new(node.clone())),
                    ),
                    _ => Self::invalid_witness_err(2, traverser),
                }
            }
            WitnessEntry::Instruction(Instruction::Code(c)) => {
                Self::traverser_replace_prev_n_nodes_entry_helper(1, traverser, NodeEntry::Code(c))
            }
            WitnessEntry::Instruction(Instruction::AccountLeaf(k, n, b, has_code, has_storage)) => {
                let (n_nodes_to_replace, account_node_code, s_trie) = match (has_code, has_storage)
                {
                    (false, false) => Self::match_account_leaf_no_code_and_no_storage(),
                    (false, true) => {
                        Self::match_account_leaf_no_code_but_has_storage(traverser, buf)
                    }
                    (true, false) => {
                        Self::match_account_leaf_has_code_but_no_storage(traverser, buf)
                    }
                    (true, true) => Self::match_account_leaf_has_code_and_storage(traverser, buf),
                }?;

                let account_leaf_data = AccountNodeData::new(n, b, s_trie, account_node_code);
                let leaf_node = WitnessEntry::Node(NodeEntry::Leaf(
                    k,
                    LeafNodeData::Account(account_leaf_data),
                ));
                traverser.replace_prev_n_entries_with_single_entry(n_nodes_to_replace, leaf_node);

                Ok(1)
            }
            WitnessEntry::Instruction(Instruction::Branch(mask)) => {
                Self::process_branch_instr(traverser, buf, mask)
            }
            _ => Ok(0),
        }
    }

    fn process_branch_instr(
        traverser: &mut CollapsableWitnessEntryTraverser,
        buf: &mut Vec<WitnessEntry>,
        mask: BranchMask,
    ) -> CompactParsingResult<usize> {
        let expected_number_of_preceding_nodes = mask.count_ones() as usize;

        traverser.get_prev_n_elems_into_buf(expected_number_of_preceding_nodes, buf);
        let number_available_preceding_elems = buf.len();

        if buf.len() != expected_number_of_preceding_nodes {
            return Err(CompactParsingError::IncorrectNumberOfNodesPrecedingBranch(
                mask,
                expected_number_of_preceding_nodes,
                number_available_preceding_elems,
                buf.clone(),
            ));
        }

        let mut branch_nodes = Self::create_empty_branch_node_entry();
        let mut curr_traverser_node_idx = 0;

        for (i, branch_node) in branch_nodes
            .iter_mut()
            .enumerate()
            .take(BRANCH_MAX_CHILDREN)
        {
            if mask as usize & (1 << i) != 0 {
                let entry_to_check = &buf[buf.len() - 1 - curr_traverser_node_idx];
                let node_entry = try_get_node_entry_from_witness_entry(entry_to_check)
                    .ok_or_else(|| {
                        let n_entries_behind_cursor =
                            number_available_preceding_elems - curr_traverser_node_idx;

                        CompactParsingError::UnexpectedPrecedingNodeFoundWhenProcessingRule(
                            n_entries_behind_cursor,
                            "Branch",
                            entry_to_check.to_string(),
                            buf.clone(),
                        )
                    })?
                    .clone();

                *branch_node = Some(Box::new(node_entry));
                curr_traverser_node_idx += 1;
            }
        }

        let number_of_nodes_traversed = curr_traverser_node_idx; // For readability.
        if curr_traverser_node_idx != buf.len() {
            return Err(CompactParsingError::MissingExpectedNodesPrecedingBranch(
                expected_number_of_preceding_nodes,
                number_of_nodes_traversed,
                mask,
                buf.clone(),
            ));
        }

        traverser.replace_prev_n_entries_with_single_entry(
            number_of_nodes_traversed + 1,
            NodeEntry::Branch(branch_nodes).into(),
        );
        Ok(1)
    }

    // ... Because we can't do `[None; 16]` without implementing `Copy`.
    fn create_empty_branch_node_entry() -> [Option<Box<NodeEntry>>; 16] {
        [
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None,
        ]
    }

    fn match_account_leaf_no_code_and_no_storage(
    ) -> CompactParsingResult<(usize, Option<AccountNodeCode>, Option<HashedPartialTrie>)> {
        Ok((1, None, None))
    }

    fn match_account_leaf_no_code_but_has_storage(
        traverser: &mut CollapsableWitnessEntryTraverser,
        buf: &mut Vec<WitnessEntry>,
    ) -> CompactParsingResult<(usize, Option<AccountNodeCode>, Option<HashedPartialTrie>)> {
        traverser.get_prev_n_elems_into_buf(1, buf);

        match buf[0].clone() {
            WitnessEntry::Node(node) => {
                Self::try_create_and_insert_partial_trie_from_node(&node, None, 2, traverser)
            }
            _ => Self::invalid_witness_err(2, traverser),
        }
    }

    fn match_account_leaf_has_code_but_no_storage(
        traverser: &mut CollapsableWitnessEntryTraverser,
        buf: &mut Vec<WitnessEntry>,
    ) -> CompactParsingResult<(usize, Option<AccountNodeCode>, Option<HashedPartialTrie>)> {
        traverser.get_prev_n_elems_into_buf(1, buf);

        match buf[0].clone() {
            WitnessEntry::Node(NodeEntry::Code(code)) => {
                Ok((2, Some(AccountNodeCode::CodeNode(code.clone())), None))
            }
            WitnessEntry::Node(NodeEntry::Hash(h)) => {
                Ok((2, Some(AccountNodeCode::HashNode(h)), None))
            }
            _ => Self::invalid_witness_err(2, traverser),
        }
    }

    fn match_account_leaf_has_code_and_storage(
        traverser: &mut CollapsableWitnessEntryTraverser,
        buf: &mut Vec<WitnessEntry>,
    ) -> CompactParsingResult<(usize, Option<AccountNodeCode>, Option<HashedPartialTrie>)> {
        traverser.get_prev_n_elems_into_buf(2, buf);

        match &buf[0..=1] {
            [WitnessEntry::Node(node), WitnessEntry::Node(NodeEntry::Code(c_bytes))] => {
                Self::try_create_and_insert_partial_trie_from_node(
                    node,
                    Some(c_bytes.clone().into()),
                    3,
                    traverser,
                )
            }
            [WitnessEntry::Node(node), WitnessEntry::Node(NodeEntry::Hash(c_hash))] => {
                Self::try_create_and_insert_partial_trie_from_node(
                    node,
                    Some((*c_hash).into()),
                    3,
                    traverser,
                )
            }
            _ => Self::invalid_witness_err(3, traverser),
        }
    }

    fn parse_mpt(mut self) -> CompactParsingResult<StateTrieExtractionOutput> {
        let mut entry_buf = Vec::new();

        loop {
            let num_rules_applied = self.apply_rules_to_witness_entries(&mut entry_buf)?;

            if num_rules_applied == 0 {
                break;
            }
        }

        let res = match self.entries.len() {
            1 => create_mpt_trie_from_remaining_witness_elem(self.entries.pop().unwrap()),

            // Case for when nothing except the header is passed in.
            0 => Ok(StateTrieExtractionOutput::default()),
            _ => Err(CompactParsingError::NonSingleEntryAfterProcessing(
                self.entries,
            )),
        }?;

        Ok(res)
    }

    fn try_create_and_insert_partial_trie_from_node(
        node: &NodeEntry,
        account_node_code: Option<AccountNodeCode>,
        n: usize,
        traverser: &mut CollapsableWitnessEntryTraverser,
    ) -> CompactParsingResult<(usize, Option<AccountNodeCode>, Option<HashedPartialTrie>)> {
        match Self::try_get_storage_root_node(node) {
            Some(storage_root_node) => {
                let s_trie_out = create_storage_mpt_trie_from_compact_node(storage_root_node)?;
                Ok((n, account_node_code, Some(s_trie_out.trie)))
            }
            None => Self::invalid_witness_err(n, traverser),
        }
    }

    fn try_get_storage_root_node(node: &NodeEntry) -> Option<NodeEntry> {
        match node {
            NodeEntry::Code(_) => None,
            _ => Some(node.clone()),
        }
    }

    fn invalid_witness_err<T>(
        n: usize,
        traverser: &mut CollapsableWitnessEntryTraverser,
    ) -> CompactDecodingResult<T> {
        let adjacent_elems_buf = traverser.get_prev_n_elems(n).cloned().collect();

        Err(CompactParsingError::InvalidWitnessFormat(
            adjacent_elems_buf,
        ))
    }

    fn traverser_replace_prev_n_nodes_entry_helper(
        n: usize,
        traverser: &mut CollapsableWitnessEntryTraverser,
        entry: NodeEntry,
    ) -> CompactParsingResult<usize> {
        traverser.replace_prev_n_entries_with_single_entry(n, WitnessEntry::Node(entry));
        Ok(1)
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MptPartialTriePreImages {
    pub state: HashedPartialTrie,
    pub storage: HashMap<HashedAccountAddr, HashedPartialTrie>,
}

/// Processes the compact prestate into the trie format of `mpt_trie`.
pub fn process_compact_mpt_prestate(
    state: MptTrieCompact,
) -> CompactParsingResult<ProcessedCompactOutput<StateTrieExtractionOutput>> {
    process_compact_prestate_common(
        state.0,
        ParserState::create_and_extract_header_mpt,
        ParserState::parse_mpt,
    )
}

/// Processes the compact prestate into the trie format of `mpt_trie`. Also
/// enables heavy debug traces during processing.
// TODO: Move behind a feature flag...
pub fn process_compact_mpt_prestate_debug(
    state: MptTrieCompact,
) -> CompactParsingResult<ProcessedCompactOutput<StateTrieExtractionOutput>> {
    process_compact_prestate_common(
        state.0,
        ParserState::create_and_extract_header_debug_mpt,
        ParserState::parse_mpt,
    )
}

// TODO: Move behind a feature flag just used for debugging (but probably not
// `debug`)...
#[allow(dead_code)]
fn parse_just_to_instructions(bytes: Vec<u8>) -> CompactParsingResult<Vec<Instruction>> {
    let witness_bytes = WitnessBytes::<DebugCompactCursor>::new(bytes);
    let (_, entries) = witness_bytes.process_into_instructions_and_header()?;

    Ok(entries
        .intern
        .into_iter()
        .map(|entry| match entry {
            WitnessEntry::Instruction(instr) => instr,
            _ => unreachable!(
                "Found a non-instruction at a stage when we should only have instructions!"
            ),
        })
        .collect())
}

// Using struct to make printing this nicer easier.
#[derive(Debug)]
struct InstructionAndBytesParsedFromBuf(Vec<(Instruction, Vec<u8>)>);

impl From<Vec<(Instruction, Vec<u8>)>> for InstructionAndBytesParsedFromBuf {
    fn from(v: Vec<(Instruction, Vec<u8>)>) -> Self {
        Self(v)
    }
}

impl Display for InstructionAndBytesParsedFromBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Instructions and bytes there were parsed from:")?;

        for (instr, parsed_from_bytes) in &self.0 {
            writeln!(
                f,
                "Instruction: {}, Bytes: {}",
                instr,
                hex::encode(parsed_from_bytes)
            )?;
        }

        Ok(())
    }
}
