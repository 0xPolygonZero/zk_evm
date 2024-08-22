//! An EVM interpreter, allowing to execute the zkEVM CPU without keeping track
//! of co-processor operations to fill out their execution traces.
//! This is useful for testing and debugging purposes, but also in the context
//! of jumpdest analysis simulation, where it allows the prover to skim through
//! the future execution and generate nondeterministically the corresponding
//! jumpdest table, before the actual CPU carries on with contract execution.

use std::collections::{BTreeSet, HashMap};

use anyhow::anyhow;
use ethereum_types::{BigEndianHash, U256};
use log::Level;
use mpt_trie::partial_trie::PartialTrie;
use plonky2::field::types::Field;
use serde::{Deserialize, Serialize};

use crate::byte_packing::byte_packing_stark::BytePackingOp;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::generation::debug_inputs;
use crate::generation::mpt::{load_linked_lists_and_txn_and_receipt_mpts, TrieRootPtrs};
use crate::generation::rlp::all_rlp_prover_inputs_reversed;
use crate::generation::state::{
    all_ger_prover_inputs_reversed, all_withdrawals_prover_inputs_reversed, GenerationState,
    GenerationStateCheckpoint,
};
use crate::generation::{state::State, GenerationInputs};
use crate::keccak_sponge::columns::KECCAK_WIDTH_BYTES;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeOp;
use crate::memory::segments::Segment;
use crate::util::h2u;
use crate::witness::errors::ProgramError;
use crate::witness::memory::{
    MemoryAddress, MemoryContextState, MemoryOp, MemoryOpKind, MemorySegmentState, MemoryState,
};
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
    #[allow(unused)]
    pub(crate) opcode_count: [usize; 0x100],
    jumpdest_table: HashMap<usize, BTreeSet<usize>>,
    /// `true` if the we are currently carrying out a jumpdest analysis.
    pub(crate) is_jumpdest_analysis: bool,
    /// Holds the value of the clock: the clock counts the number of operations
    /// in the execution.
    pub(crate) clock: usize,
    /// Log of the maximal number of CPU cycles in one segment execution.
    max_cpu_len_log: Option<usize>,
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
            let mut interpreter = Interpreter::new_with_state_and_halt_condition(
                state,
                halt_pc,
                initial_context,
                None,
            );

            log::debug!("Simulating CPU for jumpdest analysis.");

            let _ = interpreter.run();

            log::trace!("jumpdest table = {:?}", interpreter.jumpdest_table);

            let clock = interpreter.get_clock();

            interpreter
                .generation_state
                .set_jumpdest_analysis_inputs(interpreter.jumpdest_table);

            log::debug!(
                "Simulated CPU for jumpdest analysis halted after {:?} cycles.",
                clock
            );

            interpreter.generation_state.jumpdest_table
        }
    }
}

/// State data required to initialize the state passed to the prover.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExtraSegmentData {
    pub(crate) bignum_modmul_result_limbs: Vec<U256>,
    pub(crate) rlp_prover_inputs: Vec<U256>,
    pub(crate) withdrawal_prover_inputs: Vec<U256>,
    pub(crate) ger_prover_inputs: Vec<U256>,
    pub(crate) trie_root_ptrs: TrieRootPtrs,
    pub(crate) jumpdest_table: Option<HashMap<usize, Vec<usize>>>,
    pub(crate) next_txn_index: usize,
}

pub(crate) fn set_registers_and_run<F: Field>(
    registers: RegistersState,
    interpreter: &mut Interpreter<F>,
) -> anyhow::Result<(RegistersState, Option<MemoryState>)> {
    interpreter.generation_state.registers = registers;
    interpreter.generation_state.registers.program_counter = KERNEL.global_labels["init"];
    interpreter.generation_state.registers.is_kernel = true;
    interpreter.clock = 0;

    // Write initial registers.
    [
        registers.program_counter.into(),
        (registers.is_kernel as usize).into(),
        registers.stack_len.into(),
        registers.stack_top,
        registers.context.into(),
        registers.gas_used.into(),
    ]
    .iter()
    .enumerate()
    .for_each(|(i, reg_content)| {
        interpreter.generation_state.memory.set(
            MemoryAddress::new(0, Segment::RegistersStates, i),
            *reg_content,
        )
    });

    interpreter.run()
}

impl<F: Field> Interpreter<F> {
    /// Returns an instance of `Interpreter` given `GenerationInputs`, and
    /// assuming we are initializing with the `KERNEL` code.
    pub(crate) fn new_with_generation_inputs(
        initial_offset: usize,
        initial_stack: Vec<U256>,
        inputs: &GenerationInputs,
        max_cpu_len_log: Option<usize>,
    ) -> Self {
        debug_inputs(inputs);

        let mut result = Self::new(initial_offset, initial_stack, max_cpu_len_log);
        result.initialize_interpreter_state(inputs);
        result
    }

    pub(crate) fn new(
        initial_offset: usize,
        initial_stack: Vec<U256>,
        max_cpu_len_log: Option<usize>,
    ) -> Self {
        let mut interpreter = Self {
            generation_state: GenerationState::new(&GenerationInputs::default(), &KERNEL.code)
                .expect("Default inputs are known-good"),
            // `DEFAULT_HALT_OFFSET` is used as a halting point for the interpreter,
            // while the label `halt` is the halting label in the kernel.
            halt_offsets: vec![DEFAULT_HALT_OFFSET, KERNEL.global_labels["halt_final"]],
            halt_context: None,
            opcode_count: [0; 256],
            jumpdest_table: HashMap::new(),
            is_jumpdest_analysis: false,
            clock: 0,
            max_cpu_len_log,
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
        max_cpu_len_log: Option<usize>,
    ) -> Self {
        Self {
            generation_state: state.soft_clone(),
            halt_offsets: vec![halt_offset],
            halt_context: Some(halt_context),
            opcode_count: [0; 256],
            jumpdest_table: HashMap::new(),
            is_jumpdest_analysis: true,
            clock: 0,
            max_cpu_len_log,
        }
    }

    /// Initializes the interpreter state given `GenerationInputs`.
    pub(crate) fn initialize_interpreter_state(&mut self, inputs: &GenerationInputs) {
        // Initialize registers.
        let registers_before = RegistersState::new();
        self.generation_state.registers = RegistersState {
            program_counter: self.generation_state.registers.program_counter,
            is_kernel: self.generation_state.registers.is_kernel,
            ..registers_before
        };

        let tries = &inputs.tries;

        // Set state's inputs. We trim unnecessary components.
        self.generation_state.inputs = inputs.trim();

        // Initialize the MPT's pointers.
        let (trie_root_ptrs, state_leaves, storage_leaves, trie_data) =
            load_linked_lists_and_txn_and_receipt_mpts(&inputs.tries)
                .expect("Invalid MPT data for preinitialization");

        let trie_roots_after = &inputs.trie_roots_after;
        self.generation_state.trie_root_ptrs = trie_root_ptrs;

        // Initialize the `TrieData` segment.
        let preinit_trie_data_segment = MemorySegmentState { content: trie_data };
        let preinit_accounts_ll_segment = MemorySegmentState {
            content: state_leaves,
        };
        let preinit_storage_ll_segment = MemorySegmentState {
            content: storage_leaves,
        };
        self.insert_preinitialized_segment(Segment::TrieData, preinit_trie_data_segment);
        self.insert_preinitialized_segment(
            Segment::AccountsLinkedList,
            preinit_accounts_ll_segment,
        );
        self.insert_preinitialized_segment(Segment::StorageLinkedList, preinit_storage_ll_segment);

        // Update the RLP and withdrawal prover inputs.
        let rlp_prover_inputs = all_rlp_prover_inputs_reversed(&inputs.signed_txns);
        let withdrawal_prover_inputs = all_withdrawals_prover_inputs_reversed(&inputs.withdrawals);
        let ger_prover_inputs = all_ger_prover_inputs_reversed(&inputs.global_exit_roots);
        self.generation_state.rlp_prover_inputs = rlp_prover_inputs;
        self.generation_state.withdrawal_prover_inputs = withdrawal_prover_inputs;
        self.generation_state.ger_prover_inputs = ger_prover_inputs;

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
            (
                GlobalMetadata::BlockBlobGasUsed,
                metadata.block_blob_gas_used,
            ),
            (
                GlobalMetadata::BlockExcessBlobGas,
                metadata.block_excess_blob_gas,
            ),
            (
                GlobalMetadata::ParentBeaconBlockRoot,
                h2u(metadata.parent_beacon_block_root),
            ),
            (GlobalMetadata::BlockGasUsedBefore, inputs.gas_used_before),
            (GlobalMetadata::BlockGasUsedAfter, inputs.gas_used_after),
            (GlobalMetadata::TxnNumberBefore, inputs.txn_number_before),
            (
                GlobalMetadata::TxnNumberAfter,
                inputs.txn_number_before + inputs.signed_txns.len(),
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
            (GlobalMetadata::KernelHash, h2u(KERNEL.code_hash)),
            (GlobalMetadata::KernelLen, KERNEL.code.len().into()),
        ];

        self.set_global_metadata_multi_fields(&global_metadata_to_set);

        // Set final block bloom values.
        let final_block_bloom_fields = (0..8)
            .map(|i| {
                (
                    MemoryAddress::new(0, Segment::GlobalBlockBloom, i),
                    metadata.block_bloom[i],
                )
            })
            .collect::<Vec<_>>();

        self.set_memory_multi_addresses(&final_block_bloom_fields);

        // Set previous block hash.
        let block_hashes_fields = (0..256)
            .map(|i| {
                (
                    MemoryAddress::new(0, Segment::BlockHashes, i),
                    h2u(inputs.block_hashes.prev_hashes[i]),
                )
            })
            .collect::<Vec<_>>();

        self.set_memory_multi_addresses(&block_hashes_fields);

        // Write initial registers.
        let registers_before = [
            registers_before.program_counter.into(),
            (registers_before.is_kernel as usize).into(),
            registers_before.stack_len.into(),
            registers_before.stack_top,
            registers_before.context.into(),
            registers_before.gas_used.into(),
        ];
        let registers_before_fields = (0..registers_before.len())
            .map(|i| {
                (
                    MemoryAddress::new(0, Segment::RegistersStates, i),
                    registers_before[i],
                )
            })
            .collect::<Vec<_>>();

        self.set_memory_multi_addresses(&registers_before_fields);
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

    pub(crate) fn run(&mut self) -> Result<(RegistersState, Option<MemoryState>), anyhow::Error> {
        let (final_registers, final_mem) = self.run_cpu(self.max_cpu_len_log)?;

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

        Ok((final_registers, final_mem))
    }

    /// Returns the max number of CPU cycles.
    pub(crate) fn get_max_cpu_len_log(&self) -> Option<usize> {
        self.max_cpu_len_log
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

    // As this relies on the underlying `GenerationState` method, stacks containing
    // more than 10 elements will be truncated. As such, new tests that would need
    // to access more elements would require special handling.
    pub(crate) fn stack(&self) -> Vec<U256> {
        let mut stack = self.generation_state.stack();
        stack.reverse();

        stack
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
    /// Returns a `GenerationStateCheckpoint` to save the current registers and
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

    fn apply_ops(&mut self, _checkpoint: GenerationStateCheckpoint) {
        self.apply_memops()
            .expect("We should not have nonzero initial values in non-preinitialized segments");
    }

    fn get_stack(&self) -> Vec<U256> {
        let mut stack = self.stack();
        stack.reverse();

        stack
    }

    fn get_halt_offsets(&self) -> Vec<usize> {
        self.halt_offsets.clone()
    }

    fn get_active_memory(&self) -> Option<MemoryState> {
        let mut memory_state = MemoryState {
            contexts: vec![
                MemoryContextState::default();
                self.generation_state.memory.contexts.len()
            ],
            ..self.generation_state.memory.clone()
        };

        // Only copy memory from non-stale contexts
        for (ctx_idx, ctx) in self.generation_state.memory.contexts.iter().enumerate() {
            if !self
                .get_generation_state()
                .stale_contexts
                .contains(&ctx_idx)
            {
                memory_state.contexts[ctx_idx] = ctx.clone();
            }
        }

        memory_state.preinitialized_segments =
            self.generation_state.memory.preinitialized_segments.clone();

        Some(memory_state)
    }

    fn update_interpreter_final_registers(&mut self, final_registers: RegistersState) {
        {
            let registers_after = [
                final_registers.program_counter.into(),
                (final_registers.is_kernel as usize).into(),
                final_registers.stack_len.into(),
                final_registers.stack_top,
                final_registers.context.into(),
                final_registers.gas_used.into(),
            ];

            let length = registers_after.len();
            let registers_after_fields = (0..length)
                .map(|i| {
                    (
                        MemoryAddress::new(0, Segment::RegistersStates, length + i),
                        registers_after[i],
                    )
                })
                .collect::<Vec<_>>();
            self.set_memory_multi_addresses(&registers_after_fields);
        }
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
            self.log_debug(format!("User instruction: {:?}", op));
        }

        let generation_state = self.get_mut_generation_state();
        // Might write in general CPU columns when it shouldn't, but the correct values
        // will overwrite these ones during the op generation.
        if let Some(special_len) = get_op_special_length(op) {
            if generation_state.stack().len() != special_len {
                // If the `State` is an interpreter, we cannot rely on the row to carry out the
                // check.
                generation_state.registers.is_stack_top_read = true;
            }
        } else if let Some(inv) = row.stack_len.try_inverse() {
            row.general.stack_mut().stack_inv = inv;
            row.general.stack_mut().stack_inv_aux = F::ONE;
        }

        self.perform_state_op(op, row)
    }

    fn log_debug(&self, msg: String) {
        if !self.is_jumpdest_analysis {
            log::debug!("{}", msg);
        }
    }

    fn log(&self, level: Level, msg: String) {
        if !self.is_jumpdest_analysis {
            log::log!(level, "{}", msg);
        }
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
        _row: &mut crate::cpu::columns::CpuColumnsView<F>,
    ) -> Result<(), ProgramError> {
        self.generation_state.registers.is_stack_top_read = false;
        self.generation_state.registers.check_overflow = false;

        Ok(())
    }
}

#[cfg(debug_assertions)]
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
        0x4a => "BLOBBASEFEE",
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
        0x5e => "MCOPY",
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
        0xee => "PROVER_INPUT",
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
        let mut interpreter: Interpreter<F> = Interpreter::new(0, vec![], None);

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
