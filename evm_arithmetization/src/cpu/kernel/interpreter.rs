//! An EVM interpreter for testing and debugging purposes.

use core::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};

use anyhow::anyhow;
use ethereum_types::{BigEndianHash, U256};
use mpt_trie::partial_trie::PartialTrie;
use plonky2::field::types::Field;

use crate::byte_packing::byte_packing_stark::BytePackingOp;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::generation::debug_inputs;
use crate::generation::mpt::load_all_mpts;
use crate::generation::rlp::all_rlp_prover_inputs_reversed;
use crate::generation::state::{
    all_withdrawals_prover_inputs_reversed, GenerationState, GenerationStateCheckpoint,
};
use crate::generation::{state::State, GenerationInputs};
use crate::keccak_sponge::columns::KECCAK_WIDTH_BYTES;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeOp;
use crate::memory::segments::Segment;
use crate::util::h2u;
use crate::witness::errors::ProgramError;
use crate::witness::memory::{MemoryAddress, MemoryOp, MemoryOpKind, MemorySegmentState};
use crate::witness::operation::Operation;
use crate::witness::state::RegistersState;
use crate::witness::transition::{
    decode, fill_op_flag, get_op_special_length, log_kernel_instruction, Transition,
};
use crate::{arithmetic, keccak, logic};

/// Halt interpreter execution whenever a jump to this offset is done.
const DEFAULT_HALT_OFFSET: usize = 0xdeadbeef;

pub(crate) struct Interpreter<F: Field> {
    /// The interpreter holds a `GenerationState` to keep track of the memory
    /// and registers.
    pub(crate) generation_state: GenerationState<F>,
    // All offsets at which the interpreter execution halts.
    pub(crate) halt_offsets: Vec<usize>,
    /// The interpreter will halt only if the current context matches
    /// halt_context
    pub(crate) halt_context: Option<usize>,
    /// Counts the number of appearances of each opcode. For debugging purposes.
    pub(crate) opcode_count: [usize; 0x100],
    jumpdest_table: HashMap<usize, BTreeSet<usize>>,
    /// `true` if the we are currently carrying out a jumpdest analysis.
    pub(crate) is_jumpdest_analysis: bool,
    /// Holds the value of the clock: the clock counts the number of operations
    /// in the execution.
    pub(crate) clock: usize,
}

/// Structure storing the state of the interpreter's registers.
struct InterpreterRegistersState {
    kernel_mode: bool,
    context: usize,
    registers: RegistersState,
}

pub(crate) fn run_interpreter<F: Field>(
    initial_offset: usize,
    initial_stack: Vec<U256>,
) -> anyhow::Result<Interpreter<F>> {
    run(initial_offset, initial_stack)
}

#[derive(Clone)]
pub(crate) struct InterpreterMemoryInitialization {
    pub label: String,
    pub stack: Vec<U256>,
    pub segment: Segment,
    pub memory: Vec<(usize, Vec<U256>)>,
}

pub(crate) fn run_interpreter_with_memory<F: Field>(
    memory_init: InterpreterMemoryInitialization,
) -> anyhow::Result<Interpreter<F>> {
    let label = KERNEL.global_labels[&memory_init.label];
    let mut stack = memory_init.stack;
    stack.reverse();
    let mut interpreter = Interpreter::new(label, stack);
    for (pointer, data) in memory_init.memory {
        for (i, term) in data.iter().enumerate() {
            interpreter.generation_state.memory.set(
                MemoryAddress::new(0, memory_init.segment, pointer + i),
                *term,
            )
        }
    }
    interpreter.run()?;
    Ok(interpreter)
}

pub(crate) fn run<F: Field>(
    initial_offset: usize,
    initial_stack: Vec<U256>,
) -> anyhow::Result<Interpreter<F>> {
    let mut interpreter = Interpreter::new(initial_offset, initial_stack);
    interpreter.run()?;
    Ok(interpreter)
}

/// Simulates the CPU execution from `state` until the program counter reaches
/// `final_label` in the current context.
pub(crate) fn simulate_cpu_and_get_user_jumps<F: Field>(
    final_label: &str,
    state: &GenerationState<F>,
) -> Option<HashMap<usize, Vec<usize>>> {
    match state.jumpdest_table {
        Some(_) => None,
        None => {
            let halt_pc = KERNEL.global_labels[final_label];
            let initial_context = state.registers.context;
            let mut interpreter =
                Interpreter::new_with_state_and_halt_condition(state, halt_pc, initial_context);

            log::debug!("Simulating CPU for jumpdest analysis.");

            interpreter.run();

            log::trace!("jumpdest table = {:?}", interpreter.jumpdest_table);

            interpreter
                .generation_state
                .set_jumpdest_analysis_inputs(interpreter.jumpdest_table);

            log::debug!("Simulated CPU for jumpdest analysis halted.");
            interpreter.generation_state.jumpdest_table
        }
    }
}

impl<F: Field> Interpreter<F> {
    /// Returns an instance of `Interpreter` given `GenerationInputs`, and
    /// assuming we are initializing with the `KERNEL` code.
    pub(crate) fn new_with_generation_inputs(
        initial_offset: usize,
        initial_stack: Vec<U256>,
        inputs: GenerationInputs,
    ) -> Self {
        debug_inputs(&inputs);

        let mut result = Self::new(initial_offset, initial_stack);
        result.initialize_interpreter_state(inputs);
        result
    }

    pub(crate) fn new(initial_offset: usize, initial_stack: Vec<U256>) -> Self {
        let mut interpreter = Self {
            generation_state: GenerationState::new(GenerationInputs::default(), &KERNEL.code)
                .expect("Default inputs are known-good"),
            // `DEFAULT_HALT_OFFSET` is used as a halting point for the interpreter,
            // while the label `halt` is the halting label in the kernel.
            halt_offsets: vec![DEFAULT_HALT_OFFSET, KERNEL.global_labels["halt"]],
            halt_context: None,
            opcode_count: [0; 256],
            jumpdest_table: HashMap::new(),
            is_jumpdest_analysis: false,
            clock: 0,
        };
        interpreter.generation_state.registers.program_counter = initial_offset;
        let initial_stack_len = initial_stack.len();
        interpreter.generation_state.registers.stack_len = initial_stack_len;
        if !initial_stack.is_empty() {
            interpreter.generation_state.registers.stack_top = initial_stack[initial_stack_len - 1];
            *interpreter.stack_segment_mut() = initial_stack
                .iter()
                .map(|&elt| Some(elt))
                .collect::<Vec<_>>();
        }

        interpreter.initialize_rlp_segment();
        interpreter
    }

    pub(crate) fn new_with_state_and_halt_condition(
        state: &GenerationState<F>,
        halt_offset: usize,
        halt_context: usize,
    ) -> Self {
        Self {
            generation_state: state.soft_clone(),
            halt_offsets: vec![halt_offset],
            halt_context: Some(halt_context),
            opcode_count: [0; 256],
            jumpdest_table: HashMap::new(),
            is_jumpdest_analysis: true,
            clock: 0,
        }
    }

    /// Initializes the interpreter state given `GenerationInputs`.
    pub(crate) fn initialize_interpreter_state(&mut self, inputs: GenerationInputs) {
        let kernel_hash = KERNEL.code_hash;
        let kernel_code_len = KERNEL.code.len();
        let tries = &inputs.tries;

        // Set state's inputs.
        self.generation_state.inputs = inputs.clone();

        // Initialize the MPT's pointers.
        let (trie_root_ptrs, trie_data) =
            load_all_mpts(tries).expect("Invalid MPT data for preinitialization");
        let trie_roots_after = &inputs.trie_roots_after;
        self.generation_state.trie_root_ptrs = trie_root_ptrs;

        // Initialize the `TrieData` segment.
        let preinit_trie_data_segment = MemorySegmentState {
            content: trie_data.iter().map(|&elt| Some(elt)).collect::<Vec<_>>(),
        };
        self.insert_preinitialized_segment(Segment::TrieData, preinit_trie_data_segment);

        // Update the RLP and withdrawal prover inputs.
        let rlp_prover_inputs =
            all_rlp_prover_inputs_reversed(inputs.clone().signed_txn.as_ref().unwrap_or(&vec![]));
        let withdrawal_prover_inputs = all_withdrawals_prover_inputs_reversed(&inputs.withdrawals);
        self.generation_state.rlp_prover_inputs = rlp_prover_inputs;
        self.generation_state.withdrawal_prover_inputs = withdrawal_prover_inputs;

        // Set `GlobalMetadata` values.
        let metadata = &inputs.block_metadata;
        let global_metadata_to_set = [
            (
                GlobalMetadata::BlockBeneficiary,
                U256::from_big_endian(&metadata.block_beneficiary.0),
            ),
            (GlobalMetadata::BlockTimestamp, metadata.block_timestamp),
            (GlobalMetadata::BlockNumber, metadata.block_number),
            (GlobalMetadata::BlockDifficulty, metadata.block_difficulty),
            (
                GlobalMetadata::BlockRandom,
                metadata.block_random.into_uint(),
            ),
            (GlobalMetadata::BlockGasLimit, metadata.block_gaslimit),
            (GlobalMetadata::BlockChainId, metadata.block_chain_id),
            (GlobalMetadata::BlockBaseFee, metadata.block_base_fee),
            (
                GlobalMetadata::BlockCurrentHash,
                h2u(inputs.block_hashes.cur_hash),
            ),
            (GlobalMetadata::BlockGasUsed, metadata.block_gas_used),
            (GlobalMetadata::BlockGasUsedBefore, inputs.gas_used_before),
            (GlobalMetadata::BlockGasUsedAfter, inputs.gas_used_after),
            (GlobalMetadata::TxnNumberBefore, inputs.txn_number_before),
            (
                GlobalMetadata::TxnNumberAfter,
                inputs.txn_number_before + if inputs.signed_txn.is_some() { 1 } else { 0 },
            ),
            (
                GlobalMetadata::StateTrieRootDigestBefore,
                h2u(tries.state_trie.hash()),
            ),
            (
                GlobalMetadata::TransactionTrieRootDigestBefore,
                h2u(tries.transactions_trie.hash()),
            ),
            (
                GlobalMetadata::ReceiptTrieRootDigestBefore,
                h2u(tries.receipts_trie.hash()),
            ),
            (
                GlobalMetadata::StateTrieRootDigestAfter,
                h2u(trie_roots_after.state_root),
            ),
            (
                GlobalMetadata::TransactionTrieRootDigestAfter,
                h2u(trie_roots_after.transactions_root),
            ),
            (
                GlobalMetadata::ReceiptTrieRootDigestAfter,
                h2u(trie_roots_after.receipts_root),
            ),
            (GlobalMetadata::KernelHash, h2u(kernel_hash)),
            (GlobalMetadata::KernelLen, kernel_code_len.into()),
        ];

        self.set_global_metadata_multi_fields(&global_metadata_to_set);

        // Set final block bloom values.
        let final_block_bloom_fields = (0..8)
            .map(|i| {
                (
                    MemoryAddress::new_u256s(
                        U256::zero(),
                        (Segment::GlobalBlockBloom.unscale()).into(),
                        i.into(),
                    )
                    .expect("This cannot panic as `virt` fits in a `u32`"),
                    metadata.block_bloom[i],
                )
            })
            .collect::<Vec<_>>();

        self.set_memory_multi_addresses(&final_block_bloom_fields);

        // Set previous block hash.
        let block_hashes_fields = (0..256)
            .map(|i| {
                (
                    MemoryAddress::new_u256s(
                        U256::zero(),
                        (Segment::BlockHashes.unscale()).into(),
                        i.into(),
                    )
                    .expect("This cannot panic as `virt` fits in a `u32`"),
                    h2u(inputs.block_hashes.prev_hashes[i]),
                )
            })
            .collect::<Vec<_>>();

        self.set_memory_multi_addresses(&block_hashes_fields);
    }

    /// Applies all memory operations since the last checkpoint. The memory
    /// operations are cleared at each checkpoint.
    pub(crate) fn apply_memops(&mut self) -> Result<(), anyhow::Error> {
        for memop in &self.generation_state.traces.memory_ops {
            let &MemoryOp {
                kind,
                address,
                value,
                ..
            } = memop;
            match kind {
                MemoryOpKind::Read => {
                    if self.generation_state.memory.get(address).is_none() {
                        if !self.is_preinitialized_segment(address.segment) && !value.is_zero() {
                            return Err(anyhow!("The initial value {:?} at address {:?} should be zero, because it is not preinitialized.", value, address));
                        }
                        self.generation_state.memory.set(address, value);
                    }
                }
                MemoryOpKind::Write => self.generation_state.memory.set(address, value),
            }
        }

        Ok(())
    }

    pub(crate) fn run(&mut self) -> Result<(), anyhow::Error> {
        self.run_cpu()?;

        #[cfg(debug_assertions)]
        {
            println!("Opcode count:");
            for i in 0..0x100 {
                if self.opcode_count[i] > 0 {
                    println!("{}: {}", get_mnemonic(i as u8), self.opcode_count[i])
                }
            }
            println!("Total: {}", self.opcode_count.into_iter().sum::<usize>());
        }
        Ok(())
    }

    pub(crate) fn code(&self) -> &MemorySegmentState {
        // The context is 0 if we are in kernel mode.
        &self.generation_state.memory.contexts[(1 - self.is_kernel() as usize) * self.context()]
            .segments[Segment::Code.unscale()]
    }

    pub(crate) fn set_global_metadata_multi_fields(&mut self, metadata: &[(GlobalMetadata, U256)]) {
        for &(field, value) in metadata {
            let field = field.unscale();
            self.generation_state.memory.contexts[0].segments[Segment::GlobalMetadata.unscale()]
                .set(field, value);
        }
    }

    pub(crate) fn set_memory_multi_addresses(&mut self, addrs: &[(MemoryAddress, U256)]) {
        for &(addr, val) in addrs {
            self.generation_state.memory.set(addr, val);
        }
    }

    pub(crate) fn stack(&self) -> Vec<U256> {
        match self.stack_len().cmp(&1) {
            Ordering::Greater => {
                let mut stack = self.generation_state.memory.contexts[self.context()].segments
                    [Segment::Stack.unscale()]
                .content
                .iter()
                .filter_map(|&opt_elt| opt_elt)
                .collect::<Vec<_>>();
                stack.truncate(self.stack_len() - 1);
                stack.push(
                    self.stack_top()
                        .expect("The stack is checked to be nonempty"),
                );
                stack
            }
            Ordering::Equal => {
                vec![self
                    .stack_top()
                    .expect("The stack is checked to be nonempty")]
            }
            Ordering::Less => {
                vec![]
            }
        }
    }

    fn stack_segment_mut(&mut self) -> &mut Vec<Option<U256>> {
        let context = self.context();
        &mut self.generation_state.memory.contexts[context].segments[Segment::Stack.unscale()]
            .content
    }

    pub(crate) fn add_jumpdest_offset(&mut self, offset: usize) {
        if let Some(jumpdest_table) = self
            .jumpdest_table
            .get_mut(&self.generation_state.registers.context)
        {
            jumpdest_table.insert(offset);
        } else {
            self.jumpdest_table.insert(
                self.generation_state.registers.context,
                BTreeSet::from([offset]),
            );
        }
    }

    pub(crate) const fn stack_len(&self) -> usize {
        self.generation_state.registers.stack_len
    }

    pub(crate) const fn stack_top(&self) -> anyhow::Result<U256, ProgramError> {
        if self.stack_len() > 0 {
            Ok(self.generation_state.registers.stack_top)
        } else {
            Err(ProgramError::StackUnderflow)
        }
    }

    pub(crate) const fn is_kernel(&self) -> bool {
        self.generation_state.registers.is_kernel
    }

    pub(crate) const fn context(&self) -> usize {
        self.generation_state.registers.context
    }

    /// Writes the encoding of 0 at @ENCODED_EMPTY_NODE_ADDR.
    pub(crate) fn initialize_rlp_segment(&mut self) {
        self.generation_state
            .memory
            .set(MemoryAddress::new(0, Segment::RlpRaw, 0), 0x80.into())
    }

    /// Inserts a preinitialized segment, given as a [Segment],
    /// into the `preinitialized_segments` memory field.
    fn insert_preinitialized_segment(&mut self, segment: Segment, values: MemorySegmentState) {
        self.generation_state
            .memory
            .insert_preinitialized_segment(segment, values);
    }

    pub(crate) fn is_preinitialized_segment(&self, segment: usize) -> bool {
        self.generation_state
            .memory
            .is_preinitialized_segment(segment)
    }
}

impl<F: Field> State<F> for Interpreter<F> {
    //// Returns a `GenerationStateCheckpoint` to save the current registers and
    /// reset memory operations to the empty vector.
    fn checkpoint(&mut self) -> GenerationStateCheckpoint {
        self.generation_state.traces.memory_ops = vec![];
        GenerationStateCheckpoint {
            registers: self.generation_state.registers,
            traces: self.generation_state.traces.checkpoint(),
            clock: self.get_clock(),
        }
    }

    fn incr_gas(&mut self, n: u64) {
        self.generation_state.incr_gas(n);
    }

    fn incr_pc(&mut self, n: usize) {
        self.generation_state.incr_pc(n);
    }

    fn get_registers(&self) -> RegistersState {
        self.generation_state.get_registers()
    }

    fn get_mut_registers(&mut self) -> &mut RegistersState {
        self.generation_state.get_mut_registers()
    }

    fn get_from_memory(&mut self, address: MemoryAddress) -> U256 {
        self.generation_state.memory.get_with_init(address)
    }

    fn get_generation_state(&self) -> &GenerationState<F> {
        &self.generation_state
    }

    fn get_mut_generation_state(&mut self) -> &mut GenerationState<F> {
        &mut self.generation_state
    }

    fn get_clock(&self) -> usize {
        self.clock
    }

    fn push_cpu(&mut self, _val: CpuColumnsView<F>) {
        // We don't push anything, but increment the clock to match
        // an actual proof generation.
        self.clock += 1;
    }

    fn push_logic(&mut self, _op: logic::Operation) {}

    fn push_arithmetic(&mut self, _op: arithmetic::Operation) {}

    fn push_byte_packing(&mut self, _op: BytePackingOp) {}

    fn push_keccak(&mut self, _input: [u64; keccak::keccak_stark::NUM_INPUTS], _clock: usize) {}

    fn push_keccak_bytes(&mut self, _input: [u8; KECCAK_WIDTH_BYTES], _clock: usize) {}

    fn push_keccak_sponge(&mut self, _op: KeccakSpongeOp) {}

    fn rollback(&mut self, checkpoint: GenerationStateCheckpoint) {
        self.clock = checkpoint.clock;
        self.generation_state.rollback(checkpoint)
    }

    fn get_context(&self) -> usize {
        self.context()
    }

    fn get_halt_context(&self) -> Option<usize> {
        self.halt_context
    }

    fn mem_get_kernel_content(&self) -> Vec<Option<U256>> {
        self.generation_state.memory.contexts[0].segments[Segment::KernelGeneral.unscale()]
            .content
            .clone()
    }

    fn apply_ops(&mut self, checkpoint: GenerationStateCheckpoint) {
        self.apply_memops();
    }

    fn get_stack(&self) -> Vec<U256> {
        self.stack()
    }

    fn get_halt_offsets(&self) -> Vec<usize> {
        self.halt_offsets.clone()
    }

    fn try_perform_instruction(&mut self) -> Result<Operation, ProgramError> {
        let registers = self.generation_state.registers;
        let (mut row, opcode) = self.base_row();

        let op = decode(registers, opcode)?;

        fill_op_flag(op, &mut row);

        self.fill_stack_fields(&mut row)?;

        if registers.is_kernel {
            log_kernel_instruction(self, op);
        } else {
            log::debug!("User instruction: {:?}", op);
        }

        let generation_state = self.get_mut_generation_state();
        // Might write in general CPU columns when it shouldn't, but the correct values
        // will overwrite these ones during the op generation.
        if let Some(special_len) = get_op_special_length(op) {
            let special_len_f = F::from_canonical_usize(special_len);
            if (generation_state.stack().len() != special_len) {
                // If the `State` is an interpreter, we cannot rely on the row to carry out the
                // check.
                generation_state.registers.is_stack_top_read = true;
            }
        } else if let Some(inv) = row.stack_len.try_inverse() {
            row.general.stack_mut().stack_inv = inv;
            row.general.stack_mut().stack_inv_aux = F::ONE;
        }

        self.perform_state_op(opcode, op, row)
    }
}

impl<F: Field> Transition<F> for Interpreter<F> {
    fn generate_jumpdest_analysis(&mut self, dst: usize) -> bool {
        if self.is_jumpdest_analysis && !self.generation_state.registers.is_kernel {
            self.add_jumpdest_offset(dst);
            true
        } else {
            false
        }
    }

    fn skip_if_necessary(&mut self, op: Operation) -> Result<Operation, ProgramError> {
        if self.is_kernel()
            && self.is_jumpdest_analysis
            && self.generation_state.registers.program_counter
                == KERNEL.global_labels["jumpdest_analysis"]
        {
            self.generation_state.registers.program_counter =
                KERNEL.global_labels["jumpdest_analysis_end"];
            self.generation_state
                .set_jumpdest_bits(&self.generation_state.get_current_code()?);
            let opcode = self
                .code()
                .get(self.generation_state.registers.program_counter)
                .byte(0);

            decode(self.generation_state.registers, opcode)
        } else {
            Ok(op)
        }
    }

    fn fill_stack_fields(
        &mut self,
        row: &mut crate::cpu::columns::CpuColumnsView<F>,
    ) -> Result<(), ProgramError> {
        self.generation_state.registers.is_stack_top_read = false;
        self.generation_state.registers.check_overflow = false;

        Ok(())
    }
}

fn get_mnemonic(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "STOP",
        0x01 => "ADD",
        0x02 => "MUL",
        0x03 => "SUB",
        0x04 => "DIV",
        0x05 => "SDIV",
        0x06 => "MOD",
        0x07 => "SMOD",
        0x08 => "ADDMOD",
        0x09 => "MULMOD",
        0x0a => "EXP",
        0x0b => "SIGNEXTEND",
        0x0c => "ADDFP254",
        0x0d => "MULFP254",
        0x0e => "SUBFP254",
        0x0f => "SUBMOD",
        0x10 => "LT",
        0x11 => "GT",
        0x12 => "SLT",
        0x13 => "SGT",
        0x14 => "EQ",
        0x15 => "ISZERO",
        0x16 => "AND",
        0x17 => "OR",
        0x18 => "XOR",
        0x19 => "NOT",
        0x1a => "BYTE",
        0x1b => "SHL",
        0x1c => "SHR",
        0x1d => "SAR",
        0x20 => "KECCAK256",
        0x21 => "KECCAK_GENERAL",
        0x30 => "ADDRESS",
        0x31 => "BALANCE",
        0x32 => "ORIGIN",
        0x33 => "CALLER",
        0x34 => "CALLVALUE",
        0x35 => "CALLDATALOAD",
        0x36 => "CALLDATASIZE",
        0x37 => "CALLDATACOPY",
        0x38 => "CODESIZE",
        0x39 => "CODECOPY",
        0x3a => "GASPRICE",
        0x3b => "EXTCODESIZE",
        0x3c => "EXTCODECOPY",
        0x3d => "RETURNDATASIZE",
        0x3e => "RETURNDATACOPY",
        0x3f => "EXTCODEHASH",
        0x40 => "BLOCKHASH",
        0x41 => "COINBASE",
        0x42 => "TIMESTAMP",
        0x43 => "NUMBER",
        0x44 => "DIFFICULTY",
        0x45 => "GASLIMIT",
        0x46 => "CHAINID",
        0x48 => "BASEFEE",
        0x49 => "PROVER_INPUT",
        0x50 => "POP",
        0x51 => "MLOAD",
        0x52 => "MSTORE",
        0x53 => "MSTORE8",
        0x54 => "SLOAD",
        0x55 => "SSTORE",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x58 => "GETPC",
        0x59 => "MSIZE",
        0x5a => "GAS",
        0x5b => "JUMPDEST",
        0x5f => "PUSH0",
        0x60 => "PUSH1",
        0x61 => "PUSH2",
        0x62 => "PUSH3",
        0x63 => "PUSH4",
        0x64 => "PUSH5",
        0x65 => "PUSH6",
        0x66 => "PUSH7",
        0x67 => "PUSH8",
        0x68 => "PUSH9",
        0x69 => "PUSH10",
        0x6a => "PUSH11",
        0x6b => "PUSH12",
        0x6c => "PUSH13",
        0x6d => "PUSH14",
        0x6e => "PUSH15",
        0x6f => "PUSH16",
        0x70 => "PUSH17",
        0x71 => "PUSH18",
        0x72 => "PUSH19",
        0x73 => "PUSH20",
        0x74 => "PUSH21",
        0x75 => "PUSH22",
        0x76 => "PUSH23",
        0x77 => "PUSH24",
        0x78 => "PUSH25",
        0x79 => "PUSH26",
        0x7a => "PUSH27",
        0x7b => "PUSH28",
        0x7c => "PUSH29",
        0x7d => "PUSH30",
        0x7e => "PUSH31",
        0x7f => "PUSH32",
        0x80 => "DUP1",
        0x81 => "DUP2",
        0x82 => "DUP3",
        0x83 => "DUP4",
        0x84 => "DUP5",
        0x85 => "DUP6",
        0x86 => "DUP7",
        0x87 => "DUP8",
        0x88 => "DUP9",
        0x89 => "DUP10",
        0x8a => "DUP11",
        0x8b => "DUP12",
        0x8c => "DUP13",
        0x8d => "DUP14",
        0x8e => "DUP15",
        0x8f => "DUP16",
        0x90 => "SWAP1",
        0x91 => "SWAP2",
        0x92 => "SWAP3",
        0x93 => "SWAP4",
        0x94 => "SWAP5",
        0x95 => "SWAP6",
        0x96 => "SWAP7",
        0x97 => "SWAP8",
        0x98 => "SWAP9",
        0x99 => "SWAP10",
        0x9a => "SWAP11",
        0x9b => "SWAP12",
        0x9c => "SWAP13",
        0x9d => "SWAP14",
        0x9e => "SWAP15",
        0x9f => "SWAP16",
        0xa0 => "LOG0",
        0xa1 => "LOG1",
        0xa2 => "LOG2",
        0xa3 => "LOG3",
        0xa4 => "LOG4",
        0xa5 => "PANIC",
        0xc0 => "MSTORE_32BYTES_1",
        0xc1 => "MSTORE_32BYTES_2",
        0xc2 => "MSTORE_32BYTES_3",
        0xc3 => "MSTORE_32BYTES_4",
        0xc4 => "MSTORE_32BYTES_5",
        0xc5 => "MSTORE_32BYTES_6",
        0xc6 => "MSTORE_32BYTES_7",
        0xc7 => "MSTORE_32BYTES_8",
        0xc8 => "MSTORE_32BYTES_9",
        0xc9 => "MSTORE_32BYTES_10",
        0xca => "MSTORE_32BYTES_11",
        0xcb => "MSTORE_32BYTES_12",
        0xcc => "MSTORE_32BYTES_13",
        0xcd => "MSTORE_32BYTES_14",
        0xce => "MSTORE_32BYTES_15",
        0xcf => "MSTORE_32BYTES_16",
        0xd0 => "MSTORE_32BYTES_17",
        0xd1 => "MSTORE_32BYTES_18",
        0xd2 => "MSTORE_32BYTES_19",
        0xd3 => "MSTORE_32BYTES_20",
        0xd4 => "MSTORE_32BYTES_21",
        0xd5 => "MSTORE_32BYTES_22",
        0xd6 => "MSTORE_32BYTES_23",
        0xd7 => "MSTORE_32BYTES_24",
        0xd8 => "MSTORE_32BYTES_25",
        0xd9 => "MSTORE_32BYTES_26",
        0xda => "MSTORE_32BYTES_27",
        0xdb => "MSTORE_32BYTES_28",
        0xdc => "MSTORE_32BYTES_29",
        0xdd => "MSTORE_32BYTES_30",
        0xde => "MSTORE_32BYTES_31",
        0xdf => "MSTORE_32BYTES_32",
        0xf0 => "CREATE",
        0xf1 => "CALL",
        0xf2 => "CALLCODE",
        0xf3 => "RETURN",
        0xf4 => "DELEGATECALL",
        0xf5 => "CREATE2",
        0xf6 => "GET_CONTEXT",
        0xf7 => "SET_CONTEXT",
        0xf8 => "MLOAD_32BYTES",
        0xf9 => "EXIT_KERNEL",
        0xfa => "STATICCALL",
        0xfb => "MLOAD_GENERAL",
        0xfc => "MSTORE_GENERAL",
        0xfd => "REVERT",
        0xfe => "INVALID",
        0xff => "SELFDESTRUCT",
        _ => panic!("Unrecognized opcode {opcode}"),
    }
}

#[cfg(test)]
mod tests {
    use ethereum_types::U256;
    use plonky2::field::goldilocks_field::GoldilocksField as F;

    use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
    use crate::cpu::kernel::interpreter::Interpreter;
    use crate::memory::segments::Segment;
    use crate::witness::memory::MemoryAddress;
    use crate::witness::operation::CONTEXT_SCALING_FACTOR;

    #[test]
    fn test_run_with_memory() -> anyhow::Result<()> {
        //         PUSH1 0xff
        //         PUSH1 0
        //         MSTORE

        //         PUSH1 0
        //         MLOAD

        //         PUSH1 1
        //         MLOAD

        //         PUSH1 0x42
        //         PUSH1 0x27
        //         MSTORE8
        let code = [
            0x60, 0xff, 0x60, 0x0, 0x52, 0x60, 0, 0x51, 0x60, 0x1, 0x51, 0x60, 0x42, 0x60, 0x27,
            0x53,
        ];
        let mut interpreter: Interpreter<F> = Interpreter::new(0, vec![]);

        interpreter.set_code(1, code.to_vec());

        interpreter.generation_state.memory.contexts[1].segments
            [Segment::ContextMetadata.unscale()]
        .set(ContextMetadata::GasLimit.unscale(), 100_000.into());
        // Set context and kernel mode.
        interpreter.set_context(1);
        interpreter.set_is_kernel(false);
        // Set memory necessary to sys_stop.
        interpreter.generation_state.memory.set(
            MemoryAddress::new(
                1,
                Segment::ContextMetadata,
                ContextMetadata::ParentProgramCounter.unscale(),
            ),
            0xdeadbeefu32.into(),
        );
        interpreter.generation_state.memory.set(
            MemoryAddress::new(
                1,
                Segment::ContextMetadata,
                ContextMetadata::ParentContext.unscale(),
            ),
            U256::one() << CONTEXT_SCALING_FACTOR,
        );

        interpreter.run()?;

        // sys_stop returns `success` and `cum_gas_used`, that we need to pop.
        interpreter.pop().expect("Stack should not be empty");
        interpreter.pop().expect("Stack should not be empty");

        assert_eq!(interpreter.stack(), &[0xff.into(), 0xff00.into()]);
        assert_eq!(
            interpreter.generation_state.memory.contexts[1].segments[Segment::MainMemory.unscale()]
                .get(0x27),
            0x42.into()
        );
        assert_eq!(
            interpreter.generation_state.memory.contexts[1].segments[Segment::MainMemory.unscale()]
                .get(0x1f),
            0xff.into()
        );
        Ok(())
    }
}
