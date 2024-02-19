//! An EVM interpreter for testing and debugging purposes.

use core::cmp::Ordering;
use core::ops::Range;
use std::collections::{BTreeSet, HashMap};

use anyhow::{anyhow, bail};
use ethereum_types::{BigEndianHash, H160, H256, U256, U512};
use keccak_hash::keccak;
use mpt_trie::partial_trie::PartialTrie;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;

use super::assembler::BYTES_PER_OFFSET;
use super::utils::u256_from_bool;
use crate::cpu::halt;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::assembler::Kernel;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::cpu::kernel::constants::txn_fields::NormalizedTxnField;
use crate::cpu::stack::MAX_USER_STACK_SIZE;
use crate::extension_tower::BN_BASE;
use crate::generation::mpt::load_all_mpts;
use crate::generation::prover_input::ProverInputFn;
use crate::generation::rlp::all_rlp_prover_inputs_reversed;
use crate::generation::state::{
    self, all_withdrawals_prover_inputs_reversed, GenerationState, GenerationStateCheckpoint,
};
use crate::generation::{run_cpu, GenerationInputs, State};
use crate::memory::segments::{Segment, SEGMENT_SCALING_FACTOR};
use crate::util::{h2u, u256_to_u8, u256_to_usize};
use crate::witness::errors::{ProgramError, ProverInputError};
use crate::witness::gas::gas_to_charge;
use crate::witness::memory::{
    MemoryAddress, MemoryContextState, MemoryOp, MemoryOpKind, MemorySegmentState, MemoryState,
};
use crate::witness::operation::{Operation, CONTEXT_SCALING_FACTOR};
use crate::witness::state::RegistersState;
use crate::witness::traces::{TraceCheckpoint, Traces};
use crate::witness::transition::{decode, get_op_special_length, might_overflow_op};
use crate::witness::util::{push_no_write, stack_peek};
use crate::{arithmetic, logic};

type F = GoldilocksField;

/// Halt interpreter execution whenever a jump to this offset is done.
const DEFAULT_HALT_OFFSET: usize = 0xdeadbeef;

pub(crate) struct Interpreter<F: Field> {
    pub(crate) generation_state: GenerationState<F>,
    pub(crate) halt_offsets: Vec<usize>,
    // The interpreter will halt only if the current context matches halt_context
    pub(crate) halt_context: Option<usize>,
    pub(crate) debug_offsets: Vec<usize>,
    pub(crate) opcode_count: [usize; 0x100],
    memops: Vec<InterpreterMemOpKind>,
    jumpdest_table: HashMap<usize, BTreeSet<usize>>,
    pub(crate) preinitialized_segments: HashMap<Segment, MemorySegmentState>,
    pub(crate) is_jumpdest_analysis: bool,
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

            log::debug!("jdt = {:?}", interpreter.jumpdest_table);

            interpreter
                .generation_state
                .set_jumpdest_analysis_inputs(interpreter.jumpdest_table);

            log::debug!("Simulated CPU for jumpdest analysis halted.");
            interpreter.generation_state.jumpdest_table
        }
    }
}

/// Different types of Memory operations in the interpreter.
#[derive(Debug)]
pub(crate) enum InterpreterMemOpKind {
    Read(U256, MemoryAddress),
    Write(U256, MemoryAddress),
}

impl<F: Field> Interpreter<F> {
    /// Returns an instance of `Interpreter` given `GenerationInputs`, and
    /// assuming we are initializing with the `KERNEL` code.
    pub(crate) fn new_with_generation_inputs_and_kernel(
        initial_offset: usize,
        initial_stack: Vec<U256>,
        inputs: GenerationInputs,
    ) -> Self {
        let mut result = Self::new(initial_offset, initial_stack);
        result.initialize_interpreter_state_with_kernel(inputs);
        result
    }

    pub(crate) fn new(initial_offset: usize, initial_stack: Vec<U256>) -> Self {
        let mut result = Self {
            generation_state: GenerationState::new(GenerationInputs::default(), &KERNEL.code)
                .expect("Default inputs are known-good"),
            // `DEFAULT_HALT_OFFSET` is used as a halting point for the interpreter,
            // while the label `halt` is the halting label in the kernel.
            halt_offsets: vec![DEFAULT_HALT_OFFSET, KERNEL.global_labels["halt"]],
            halt_context: None,
            debug_offsets: vec![],
            opcode_count: [0; 256],
            memops: vec![],
            jumpdest_table: HashMap::new(),
            preinitialized_segments: HashMap::default(),
            is_jumpdest_analysis: false,
            clock: 0,
        };
        result.generation_state.registers.program_counter = initial_offset;
        let initial_stack_len = initial_stack.len();
        result.generation_state.registers.stack_len = initial_stack_len;
        if !initial_stack.is_empty() {
            result.generation_state.registers.stack_top = initial_stack[initial_stack_len - 1];
            *result.stack_segment_mut() = initial_stack
                .iter()
                .map(|&elt| Some(elt))
                .collect::<Vec<_>>();
        }

        result.initialize_rlp_segment();
        result
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
            debug_offsets: vec![],
            opcode_count: [0; 256],
            memops: vec![],
            jumpdest_table: HashMap::new(),
            preinitialized_segments: HashMap::new(),
            is_jumpdest_analysis: true,
            clock: 0,
        }
    }

    /// Initializes the interpreter state given `GenerationInputs`, using the
    /// KERNEL code.
    pub(crate) fn initialize_interpreter_state_with_kernel(&mut self, inputs: GenerationInputs) {
        self.initialize_interpreter_state(inputs, KERNEL.code_hash, KERNEL.code.len());
    }

    /// Initializes the interpreter state given `GenerationInputs`.
    pub(crate) fn initialize_interpreter_state(
        &mut self,
        inputs: GenerationInputs,
        kernel_hash: H256,
        kernel_code_len: usize,
    ) {
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
        self.preinitialized_segments
            .insert(Segment::TrieData, preinit_trie_data_segment);

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

    fn interpreter_pop<const N: usize>(&mut self) -> Result<[U256; N], ProgramError> {
        if self.stack_len() < N {
            return Err(ProgramError::StackUnderflow);
        }
        let new_stack_top = if self.generation_state.registers.stack_len == N {
            None
        } else {
            Some(stack_peek(&self.generation_state, N)?)
        };
        let result = core::array::from_fn(|i| {
            if i == 0 {
                self.stack_top().unwrap()
            } else {
                let address =
                    MemoryAddress::new(self.context(), Segment::Stack, self.stack_len() - 1 - i);
                let val =
                    self.generation_state
                        .memory
                        .get(address, true, &self.preinitialized_segments);
                self.push_memop(InterpreterMemOpKind::Read(val, address));
                val
            }
        });

        self.generation_state.registers.stack_len -= N;

        if let Some(val) = new_stack_top {
            self.generation_state.registers.stack_top = val;
        }

        Ok(result)
    }

    fn interpreter_push_no_write(&mut self, val: U256) -> Result<(), ProgramError> {
        self.generation_state.registers.stack_top = val;
        self.generation_state.registers.stack_len += 1;

        Ok(())
    }

    fn interpreter_push_with_write(&mut self, val: U256) -> Result<(), ProgramError> {
        if !self.is_kernel() && self.stack_len() >= MAX_USER_STACK_SIZE {
            return Err(ProgramError::StackOverflow);
        }

        if self.stack_len() > 0 {
            let addr = MemoryAddress::new(self.context(), Segment::Stack, self.stack_len() - 1);
            self.push_memop(InterpreterMemOpKind::Write(
                self.stack_top().expect("Stack is not empty."),
                addr,
            ));
        }
        self.interpreter_push_no_write(val);

        Ok(())
    }

    // Does NOT change the memory. All queued operations will be applied at the end
    // of the transition step.
    pub(crate) fn mload_queue(&mut self, context: usize, segment: Segment, offset: usize) -> U256 {
        let address = MemoryAddress::new(context, segment, offset);
        let val = self.generation_state.memory.get_option(address);
        let val = if val.is_none()
            && self.preinitialized_segments.contains_key(&segment)
            && offset
                < self
                    .preinitialized_segments
                    .get(&segment)
                    .unwrap()
                    .content
                    .len()
        {
            self.preinitialized_segments.get(&segment).unwrap().content[offset].unwrap()
        } else if val.is_none() {
            U256::zero()
        } else {
            val.unwrap()
        };
        self.push_memop(InterpreterMemOpKind::Read(val, address));
        val
    }

    // Does NOT change the memory. All queued operations will be applied at the end
    // of the transition step.
    fn mstore_queue(&mut self, context: usize, segment: Segment, offset: usize, value: U256) {
        self.push_memop(InterpreterMemOpKind::Write(
            value,
            MemoryAddress::new(context, segment, offset),
        ));
    }

    /// Applies all memory operations since the last checkpoint.
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
                    if self.generation_state.memory.get_option(address).is_none() {
                        if !self
                            .preinitialized_segments
                            .contains_key(&Segment::all()[address.segment])
                        {
                            assert_eq!(
                                value,
                                0.into(),
                                "Value {:?} read  at address {:?} should be 0",
                                value,
                                address
                            );
                        }
                        self.generation_state.memory.set(address, value);
                    }
                }
                MemoryOpKind::Write => self.generation_state.memory.set(address, value),
            }
        }

        Ok(())
    }

    /// Returns a `GenerationStateCheckpoint` to save the current registers and
    /// reset memory operations to the empty vector.
    pub(crate) fn checkpoint(&mut self) -> GenerationStateCheckpoint {
        self.generation_state.traces.memory_ops = vec![];
        GenerationStateCheckpoint {
            registers: self.generation_state.registers,
            traces: self.generation_state.traces.checkpoint(),
        }
    }

    /// Generates a segment by returning the state and memory values after
    /// `MAX_SIZE` CPU rows.
    pub(crate) fn run(&mut self) -> Result<(), anyhow::Error> {
        let mut state = State::Interpreter(self);
        run_cpu(&mut state, false)?;

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

    fn code_slice(&self, n: usize) -> Vec<u8> {
        let pc = self.generation_state.registers.program_counter;
        self.code().content[pc + 1..pc + n + 1]
            .iter()
            .map(|u256| u256.unwrap_or_default().byte(0))
            .collect::<Vec<_>>()
    }

    pub(crate) fn get_txn_field(&self, field: NormalizedTxnField) -> U256 {
        // These fields are already scaled by their respective segment.
        self.generation_state.memory.contexts[0].segments[Segment::TxnFields.unscale()]
            .get(field.unscale())
    }

    pub(crate) fn set_txn_field(&mut self, field: NormalizedTxnField, value: U256) {
        // These fields are already scaled by their respective segment.
        self.generation_state.memory.contexts[0].segments[Segment::TxnFields.unscale()]
            .set(field.unscale(), value);
    }

    pub(crate) fn get_txn_data(&self) -> Vec<U256> {
        self.generation_state.memory.contexts[0].segments[Segment::TxnData.unscale()]
            .return_content()
    }

    pub(crate) fn get_context_metadata_field(&self, ctx: usize, field: ContextMetadata) -> U256 {
        // These fields are already scaled by their respective segment.
        self.generation_state.memory.contexts[ctx].segments[Segment::ContextMetadata.unscale()]
            .get(field.unscale())
    }

    pub(crate) fn set_context_metadata_field(
        &mut self,
        ctx: usize,
        field: ContextMetadata,
        value: U256,
    ) {
        // These fields are already scaled by their respective segment.
        self.generation_state.memory.contexts[ctx].segments[Segment::ContextMetadata.unscale()]
            .set(field.unscale(), value)
    }

    pub(crate) fn get_global_metadata_field(&self, field: GlobalMetadata) -> U256 {
        // These fields are already scaled by their respective segment.
        let field = field.unscale();
        self.generation_state.memory.contexts[0].segments[Segment::GlobalMetadata.unscale()]
            .get(field)
    }

    pub(crate) fn set_global_metadata_field(&mut self, field: GlobalMetadata, value: U256) {
        // These fields are already scaled by their respective segment.
        let field = field.unscale();
        self.generation_state.memory.contexts[0].segments[Segment::GlobalMetadata.unscale()]
            .set(field, value)
    }

    pub(crate) fn set_global_metadata_multi_fields(&mut self, metadata: &[(GlobalMetadata, U256)]) {
        for &(field, value) in metadata {
            let field = field.unscale();
            self.generation_state.memory.contexts[0].segments[Segment::GlobalMetadata.unscale()]
                .set(field, value);
        }
    }

    pub(crate) fn get_trie_data(&self) -> Vec<U256> {
        self.generation_state.memory.contexts[0].segments[Segment::TrieData.unscale()]
            .content
            .iter()
            .filter_map(|&elt| elt)
            .collect::<Vec<_>>()
    }

    pub(crate) fn get_trie_data_mut(&mut self) -> &mut Vec<Option<U256>> {
        &mut self.generation_state.memory.contexts[0].segments[Segment::TrieData.unscale()].content
    }

    pub(crate) fn get_memory_segment(&self, segment: Segment) -> Vec<U256> {
        if self.preinitialized_segments.contains_key(&segment) {
            let total_len = self.generation_state.memory.contexts[0].segments[segment.unscale()]
                .content
                .len();
            let get_vals = |opt_vals: &[Option<U256>]| {
                opt_vals
                    .iter()
                    .map(|&elt| match elt {
                        Some(val) => val,
                        None => U256::zero(),
                    })
                    .collect::<Vec<U256>>()
            };
            let mut res = get_vals(&self.preinitialized_segments.get(&segment).unwrap().content);
            let init_len = res.len();
            res.extend(&get_vals(
                &self.generation_state.memory.contexts[0].segments[segment.unscale()].content
                    [init_len..],
            ));
            res
        } else {
            self.generation_state.memory.contexts[0].segments[segment.unscale()].return_content()
        }
    }

    pub(crate) fn get_memory_segment_bytes(&self, segment: Segment) -> Vec<u8> {
        let content = self.get_memory_segment(segment);
        content.iter().map(|x| x.low_u32() as u8).collect()
    }

    pub(crate) fn get_current_general_memory(&self) -> Vec<U256> {
        self.generation_state.memory.contexts[self.context()].segments
            [Segment::KernelGeneral.unscale()]
        .return_content()
    }

    pub(crate) fn get_kernel_general_memory(&self) -> Vec<U256> {
        self.get_memory_segment(Segment::KernelGeneral)
    }

    pub(crate) fn get_rlp_memory(&self) -> Vec<u8> {
        self.get_memory_segment_bytes(Segment::RlpRaw)
    }

    pub(crate) fn set_current_general_memory(&mut self, memory: Vec<U256>) {
        let context = self.context();
        self.generation_state.memory.contexts[context].segments[Segment::KernelGeneral.unscale()]
            .content = memory.iter().map(|&val| Some(val)).collect();
    }

    pub(crate) fn set_memory_segment(&mut self, segment: Segment, memory: Vec<U256>) {
        self.generation_state.memory.contexts[0].segments[segment.unscale()].content =
            memory.iter().map(|&val| Some(val)).collect();
    }

    pub(crate) fn set_memory_segment_bytes(&mut self, segment: Segment, memory: Vec<u8>) {
        self.generation_state.memory.contexts[0].segments[segment.unscale()].content = memory
            .into_iter()
            .map(|val| Some(U256::from(val)))
            .collect();
    }

    pub(crate) fn set_rlp_memory(&mut self, rlp: Vec<u8>) {
        self.set_memory_segment_bytes(Segment::RlpRaw, rlp)
    }

    pub(crate) fn clear_traces(&mut self) {
        self.generation_state.traces.arithmetic_ops = vec![];
        self.generation_state.traces.arithmetic_ops = vec![];
        self.generation_state.traces.byte_packing_ops = vec![];
        self.generation_state.traces.cpu = vec![];
        self.generation_state.traces.logic_ops = vec![];
        self.generation_state.traces.keccak_inputs = vec![];
        self.generation_state.traces.keccak_sponge_ops = vec![];
    }

    pub(crate) fn set_code(&mut self, context: usize, code: Vec<u8>) {
        assert_ne!(context, 0, "Can't modify kernel code.");
        while self.generation_state.memory.contexts.len() <= context {
            self.generation_state
                .memory
                .contexts
                .push(MemoryContextState::default());
        }
        self.generation_state.memory.set(
            MemoryAddress::new(
                context,
                Segment::ContextMetadata,
                ContextMetadata::CodeSize.unscale(),
            ),
            code.len().into(),
        );
        self.generation_state.memory.contexts[context].segments[Segment::Code.unscale()].content =
            code.into_iter().map(|val| Some(U256::from(val))).collect();
    }

    pub(crate) fn set_memory_multi_addresses(&mut self, addrs: &[(MemoryAddress, U256)]) {
        for &(addr, val) in addrs {
            self.generation_state.memory.set(addr, val);
        }
    }

    pub(crate) fn set_jumpdest_analysis_inputs(&mut self, jumps: HashMap<usize, BTreeSet<usize>>) {
        self.generation_state.set_jumpdest_analysis_inputs(jumps);
    }

    pub(crate) fn incr(&mut self, n: usize) {
        self.generation_state.registers.program_counter += n;
    }

    pub(crate) fn push_memop(&mut self, mem_op: InterpreterMemOpKind) {
        self.memops.push(mem_op);
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

    pub(crate) fn extract_kernel_memory(self, segment: Segment, range: Range<usize>) -> Vec<U256> {
        let mut output: Vec<U256> = Vec::with_capacity(range.end);
        for i in range {
            let term = self.generation_state.memory.get(
                MemoryAddress::new(0, segment, i),
                true,
                &self.preinitialized_segments,
            );
            output.push(term);
        }
        output
    }

    // Actually pushes in memory. Only used for tests.
    pub(crate) fn push(&mut self, x: U256) -> Result<(), ProgramError> {
        if !self.is_kernel() && self.stack_len() >= MAX_USER_STACK_SIZE {
            return Err(ProgramError::StackOverflow);
        }
        if self.stack_len() > 0 {
            let top = self
                .stack_top()
                .expect("The stack is checked to be nonempty");
            let cur_len = self.stack_len();
            let stack_addr = MemoryAddress::new(self.context(), Segment::Stack, cur_len - 1);
            self.generation_state.memory.set(stack_addr, top);
        }
        self.generation_state.registers.stack_top = x;
        self.generation_state.registers.stack_len += 1;

        Ok(())
    }

    fn push_bool_no_write(&mut self, x: bool) -> Result<(), ProgramError> {
        self.interpreter_push_no_write(if x { U256::one() } else { U256::zero() });

        Ok(())
    }

    /// Actually popping the memory. Only used in tests.
    pub(crate) fn pop(&mut self) -> Result<U256, ProgramError> {
        let result = stack_peek(&self.generation_state, 0);

        if self.stack_len() > 1 {
            let top = stack_peek(&self.generation_state, 1)?;
            self.generation_state.registers.stack_top = top;
        }
        self.generation_state.registers.stack_len -= 1;

        result
    }

    fn offset_name(&self) -> String {
        KERNEL.offset_name(self.generation_state.registers.program_counter)
    }

    fn offset_label(&self) -> Option<String> {
        KERNEL.offset_label(self.generation_state.registers.program_counter)
    }

    fn get_jumpdest_bit(&self, offset: usize) -> U256 {
        if self.generation_state.memory.contexts[self.context()].segments
            [Segment::JumpdestBits.unscale()]
        .content
        .len()
            > offset
        {
            self.generation_state.memory.get(
                MemoryAddress {
                    context: self.context(),
                    segment: Segment::JumpdestBits.unscale(),
                    virt: offset,
                },
                true,
                &self.preinitialized_segments,
            )
        } else {
            0.into()
        }
    }

    pub(crate) fn get_jumpdest_bits(&self, context: usize) -> Vec<bool> {
        self.generation_state.memory.contexts[context].segments[Segment::JumpdestBits.unscale()]
            .content
            .iter()
            .map(|x| x.unwrap_or_default().bit(0))
            .collect()
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

    pub(crate) fn stack_top(&self) -> anyhow::Result<U256, ProgramError> {
        if self.stack_len() > 0 {
            Ok(self.generation_state.registers.stack_top)
        } else {
            Err(ProgramError::StackUnderflow)
        }
    }

    pub(crate) const fn is_kernel(&self) -> bool {
        self.generation_state.registers.is_kernel
    }

    pub(crate) fn set_is_kernel(&mut self, is_kernel: bool) {
        self.generation_state.registers.is_kernel = is_kernel
    }

    pub(crate) const fn context(&self) -> usize {
        self.generation_state.registers.context
    }

    pub(crate) fn set_context(&mut self, context: usize) {
        if context == 0 {
            assert!(self.is_kernel());
        }
        self.generation_state.registers.context = context;
    }

    /// Writes the encoding of 0 to position @ENCODED_EMPTY_NODE_POS.
    pub(crate) fn initialize_rlp_segment(&mut self) {
        self.generation_state.memory.set(
            MemoryAddress::new(0, Segment::RlpRaw, 0xFFFFFFFF),
            128.into(),
        )
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

macro_rules! unpack_address {
    ($addr:ident) => {{
        let offset = $addr.low_u32() as usize;
        let segment = Segment::all()[($addr >> SEGMENT_SCALING_FACTOR).low_u32() as usize];
        let context = ($addr >> CONTEXT_SCALING_FACTOR).low_u32() as usize;
        (context, segment, offset)
    }};
}
pub(crate) use unpack_address;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ethereum_types::U256;
    use plonky2::field::goldilocks_field::GoldilocksField as F;

    use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
    use crate::cpu::kernel::interpreter::{run, Interpreter};
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
