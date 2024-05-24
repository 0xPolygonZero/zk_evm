//! Logic for processing the smt compact format.

use std::collections::HashMap;

use super::{
    compact_processing_common::{
        process_compact_prestate_common, CollapsableWitnessEntryTraverser, CompactCursor,
        CompactCursorFast, CompactParsingError, CompactParsingResult, DebugCompactCursor, Header,
        Instruction, NodeEntry, Opcode, ParserState, ProcessedCompactOutput, WitnessBytes,
        WitnessEntries, WitnessEntry,
    },
    compact_to_smt_trie::{
        create_smt_trie_from_remaining_witness_elem, SmtStateTrieExtractionOutput,
    },
};
use crate::{protocol_processing::ProtocolPreImageProcessing, types::CodeHash, utils::hash};

impl ParserState {
    fn parse_smt(mut self) -> CompactParsingResult<SmtStateTrieExtractionOutput> {
        let mut entry_buf = Vec::new();
        let mut code = HashMap::new();
        let node_entry = self.apply_rules_to_witness_entries_smt(&mut entry_buf, &mut code);

        create_smt_trie_from_remaining_witness_elem(node_entry, code)
    }

    pub(crate) fn create_and_extract_header_smt<C: CompactCursor>(
        witness_bytes_raw: Vec<u8>,
    ) -> CompactParsingResult<(Header, Self)> {
        let witness_bytes = WitnessBytes::<C>::new(witness_bytes_raw);
        let (header, entries) = witness_bytes.process_into_instructions_and_header_smt()?;
        let p_state = Self { entries };

        Ok((header, p_state))
    }

    fn apply_rules_to_witness_entries_smt(
        &mut self,
        entry_buf: &mut Vec<WitnessEntry>,
        code: &mut HashMap<CodeHash, Vec<u8>>,
    ) -> NodeEntry {
        let mut traverser = self.entries.create_collapsable_traverser();
        Self::try_apply_rules_to_curr_entry_smt(&mut traverser, entry_buf, code)
    }

    // TODO: Switch this to use `Result`s...
    fn try_apply_rules_to_curr_entry_smt(
        traverser: &mut CollapsableWitnessEntryTraverser,
        buf: &mut Vec<WitnessEntry>,
        code: &mut HashMap<CodeHash, Vec<u8>>,
    ) -> NodeEntry {
        buf.extend(traverser.get_next_n_elems(1).cloned());
        traverser.advance();

        match buf[buf.len() - 1].clone() {
            WitnessEntry::Instruction(Instruction::Hash(h)) => NodeEntry::Hash(h),
            WitnessEntry::Instruction(Instruction::Branch(mask)) => {
                let mut branch_nodes = Self::create_empty_branch_node_entry_smt();

                let node_entry = Self::try_apply_rules_to_curr_entry_smt(traverser, buf, code);
                match node_entry.clone() {
                    NodeEntry::SMTLeaf(_, _, _, _) => {
                        if mask == 3 {
                            if branch_nodes[0].is_none() {
                                branch_nodes[0] = Some(Box::new(node_entry));
                                branch_nodes[1] = Some(Box::new(
                                    Self::try_apply_rules_to_curr_entry_smt(traverser, buf, code),
                                ));
                            } else {
                                branch_nodes[1] = Some(Box::new(node_entry));
                            }
                        } else if mask == 2 {
                            branch_nodes[1] = Some(Box::new(node_entry));
                        } else if mask == 1 {
                            branch_nodes[0] = Some(Box::new(node_entry));
                        }
                    }
                    NodeEntry::Hash(_) => {
                        if mask == 3 {
                            if branch_nodes[0].is_none() {
                                branch_nodes[0] = Some(Box::new(node_entry));
                                branch_nodes[1] = Some(Box::new(
                                    Self::try_apply_rules_to_curr_entry_smt(traverser, buf, code),
                                ));
                            } else {
                                branch_nodes[1] = Some(Box::new(node_entry));
                            }
                        } else if mask == 2 {
                            branch_nodes[1] = Some(Box::new(node_entry));
                        } else if mask == 1 {
                            branch_nodes[0] = Some(Box::new(node_entry));
                        }
                    }
                    NodeEntry::BranchSMT(_) => {
                        if mask == 3 {
                            if branch_nodes[0].is_none() {
                                branch_nodes[0] = Some(Box::new(node_entry));
                                branch_nodes[1] = Some(Box::new(
                                    Self::try_apply_rules_to_curr_entry_smt(traverser, buf, code),
                                ));
                            } else {
                                branch_nodes[1] = Some(Box::new(node_entry));
                            }
                        } else if mask == 2 {
                            branch_nodes[1] = Some(Box::new(node_entry));
                        } else if mask == 1 {
                            branch_nodes[0] = Some(Box::new(node_entry));
                        }
                    }
                    _ => {}
                }
                NodeEntry::BranchSMT(branch_nodes)
            }

            // TODO: Move out into separate module...
            WitnessEntry::Instruction(Instruction::SMTLeaf(
                node_type_byte,
                address,
                storage,
                value,
            )) => NodeEntry::SMTLeaf(node_type_byte, address, storage, value),
            WitnessEntry::Instruction(Instruction::Code(c_bytes)) => {
                let c_hash = hash(&c_bytes);
                code.insert(c_hash, c_bytes);
                Self::try_apply_rules_to_curr_entry_smt(traverser, buf, code)
            }
            _ => NodeEntry::Empty,
        }
    }

    // ... Because we can't do `[None; 2]` without implementing `Copy`.
    fn create_empty_branch_node_entry_smt() -> [Option<Box<NodeEntry>>; 2] {
        [None, None]
    }
}

impl<C: CompactCursor> WitnessBytes<C> {
    fn process_data_following_opcode_smt(&mut self, opcode: Opcode) -> CompactParsingResult<()> {
        match opcode {
            Opcode::Leaf => self.process_leaf(),
            Opcode::Extension => self.process_extension(),
            Opcode::Branch => self.process_branch(),
            Opcode::Hash => self.process_hash(),
            Opcode::Code => self.process_code(),
            Opcode::AccountLeaf => self.process_account_leaf(),
            Opcode::EmptyRoot => self.process_empty_root(),
            Opcode::SMTLeaf => self.process_smt_leaf(),
        }
    }

    fn process_operator_smt(&mut self) -> CompactParsingResult<()> {
        let opcode_byte = self.byte_cursor.read_byte()?;

        let opcode: Opcode =
            Opcode::n(opcode_byte).ok_or(CompactParsingError::InvalidOpcode(opcode_byte))?;

        self.process_data_following_opcode_smt(opcode)
    }

    fn process_into_instructions_and_header_smt(
        mut self,
    ) -> CompactParsingResult<(Header, WitnessEntries)> {
        let header = self.parse_header()?;

        loop {
            if self.byte_cursor.at_eof() {
                break;
            }

            self.process_operator_smt()?;
        }

        Ok((header, self.instrs))
    }
}

fn process_compact_smt_prestate(
    state: Vec<u8>,
) -> CompactParsingResult<ProcessedCompactOutput<SmtStateTrieExtractionOutput>> {
    process_compact_prestate_common(
        state,
        ParserState::create_and_extract_header_smt::<CompactCursorFast>,
        ParserState::parse_smt,
    )
}

/// Processes the compact prestate into the trie format of `smt_trie`. Also
/// enables heavy debug traces during processing.
// TODO: Move behind a feature flag...
fn process_compact_smt_prestate_debug(
    state: Vec<u8>,
) -> CompactParsingResult<ProcessedCompactOutput<SmtStateTrieExtractionOutput>> {
    process_compact_prestate_common(
        state,
        ParserState::create_and_extract_header_smt::<DebugCompactCursor>,
        ParserState::parse_smt,
    )
}

pub(crate) struct SmtPreImageProcessing;

const SMT_HEADER_VERSION: u8 = 1;

impl ProtocolPreImageProcessing for SmtPreImageProcessing {
    type ProcessedPreImage = SmtStateTrieExtractionOutput;

    fn process_image(
        bytes: Vec<u8>,
    ) -> CompactParsingResult<ProcessedCompactOutput<Self::ProcessedPreImage>> {
        process_compact_smt_prestate(bytes)
    }

    fn process_image_debug(
        bytes: Vec<u8>,
    ) -> CompactParsingResult<ProcessedCompactOutput<Self::ProcessedPreImage>> {
        process_compact_smt_prestate_debug(bytes)
    }

    fn expected_header_version() -> u8 {
        SMT_HEADER_VERSION
    }
}
