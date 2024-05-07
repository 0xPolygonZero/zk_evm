//! Logic for processing the smt compact format.

use std::collections::HashMap;

use super::{
    compact_processing_common::{
        process_compact_prestate_common, CollapsableWitnessEntryTraverser, CompactCursor,
        CompactParsingError, CompactParsingResult, DebugCompactCursor, Header, Instruction,
        NodeEntry, Opcode, ParserState, ProcessedCompactOutput, WitnessBytes, WitnessEntries,
        WitnessEntry,
    },
    compact_to_smt_trie::{
        create_smt_trie_from_remaining_witness_elem, SmtStateTrieExtractionOutput,
    },
};
use crate::{trace_protocol::SingleSmtPreImage, types::CodeHash, utils::hash};

/// Byte to encode the type of node the SMT leaf represents.
// `enumn` (`N`) generates public functions that are missing documentation, so I think we need to
// disable missing doc checks here.
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SmtLeafNodeType {
    /// Node contains the balance for a account.
    Balance = 0,
    /// Node contains the nonce for a account.
    Nonce = 1,
    /// Node contains the contract code hash for a account.
    Code = 2,
    /// Node contains the storage root for a account.
    Storage = 3,
    /// Node contains the length of the contract bytecode for an account.
    CodeLength = 4,
}

impl SmtLeafNodeType {
    pub(crate) fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Balance),
            1 => Some(Self::Nonce),
            2 => Some(Self::Code),
            3 => Some(Self::Storage),
            4 => Some(Self::CodeLength),
            _ => None,
        }
    }
}

impl ParserState {
    fn parse_smt(mut self) -> CompactParsingResult<SmtStateTrieExtractionOutput> {
        let mut entry_buf = Vec::new();
        let mut code = HashMap::new();
        let node_entry = self.apply_rules_to_witness_entries_smt(&mut entry_buf, &mut code);

        create_smt_trie_from_remaining_witness_elem(node_entry, code)
    }

    pub(crate) fn create_and_extract_header_debug_smt(
        witness_bytes_raw: Vec<u8>,
    ) -> CompactParsingResult<(Header, Self)> {
        let witness_bytes: WitnessBytes<DebugCompactCursor> =
            WitnessBytes::<DebugCompactCursor>::new(witness_bytes_raw);
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

/// Processes the compact prestate into the trie format of `smt_trie`. Also
/// enables heavy debug traces during processing.
// TODO: Move behind a feature flag...
pub fn process_compact_smt_prestate_debug(
    state: SingleSmtPreImage,
) -> CompactParsingResult<ProcessedCompactOutput<SmtStateTrieExtractionOutput>> {
    process_compact_prestate_common(
        state.0,
        ParserState::create_and_extract_header_debug_smt,
        ParserState::parse_smt,
    )
}
