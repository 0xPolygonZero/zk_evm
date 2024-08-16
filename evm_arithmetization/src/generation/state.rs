use std::collections::HashMap;
use std::mem::size_of;

use anyhow::{anyhow, bail};
use ethereum_types::{Address, BigEndianHash, H160, H256, U256};
use itertools::Itertools;
use keccak_hash::keccak;
use log::Level;
use plonky2::field::types::Field;

use super::mpt::TrieRootPtrs;
use super::{TrieInputs, TrimmedGenerationInputs, NUM_EXTRA_CYCLES_AFTER};
use crate::byte_packing::byte_packing_stark::BytePackingOp;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::stack::MAX_USER_STACK_SIZE;
use crate::generation::mpt::load_linked_lists_and_txn_and_receipt_mpts;
use crate::generation::rlp::all_rlp_prover_inputs_reversed;
use crate::generation::CpuColumnsView;
use crate::generation::GenerationInputs;
use crate::keccak_sponge::columns::KECCAK_WIDTH_BYTES;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeOp;
use crate::memory::segments::Segment;
use crate::prover::GenerationSegmentData;
use crate::util::u256_to_usize;
use crate::witness::errors::ProgramError;
use crate::witness::memory::MemoryChannel::GeneralPurpose;
use crate::witness::memory::MemoryOpKind;
use crate::witness::memory::{MemoryAddress, MemoryOp, MemoryState};
use crate::witness::operation::{generate_exception, Operation};
use crate::witness::state::RegistersState;
use crate::witness::traces::{TraceCheckpoint, Traces};
use crate::witness::transition::{
    decode, fill_op_flag, get_op_special_length, log_kernel_instruction, might_overflow_op,
    read_code_memory, Transition,
};
use crate::witness::util::{fill_channel_with_value, stack_peek};
use crate::{arithmetic, keccak, logic};

/// A State is either an `Interpreter` (used for tests and jumpdest analysis) or
/// a `GenerationState`.
pub(crate) trait State<F: Field> {
    /// Returns a `State`'s latest `Checkpoint`.
    fn checkpoint(&mut self) -> GenerationStateCheckpoint;

    /// Increments the `gas_used` register by a value `n`.
    fn incr_gas(&mut self, n: u64);

    /// Increments the `program_counter` register by a value `n`.
    fn incr_pc(&mut self, n: usize);

    /// Returns a `RegistersState`.
    fn get_registers(&self) -> RegistersState;

    /// Returns a reference to this `State`s `GenerationState`.
    fn get_generation_state(&self) -> &GenerationState<F>;

    /// Returns a mutable reference to the `State`'s registers.
    fn get_mut_registers(&mut self) -> &mut RegistersState;

    /// Returns the value stored at address `address` in a `State`, or 0 if the
    /// memory is unset at this position.
    fn get_from_memory(&mut self, address: MemoryAddress) -> U256;

    /// Returns a mutable reference to a `State`'s `GenerationState`.
    fn get_mut_generation_state(&mut self) -> &mut GenerationState<F>;

    /// Returns the value of a `State`'s clock.
    fn get_clock(&self) -> usize;

    /// Rolls back a `State`.
    fn rollback(&mut self, checkpoint: GenerationStateCheckpoint);

    /// Returns a `State`'s stack.
    fn get_stack(&self) -> Vec<U256>;

    /// Returns the current context.
    fn get_context(&self) -> usize;

    /// Checks whether we have reached the maximal cpu length.
    fn at_end_segment(&self, opt_cycle_limit: Option<usize>) -> bool {
        if let Some(cycle_limit) = opt_cycle_limit {
            self.get_clock() == cycle_limit
        } else {
            false
        }
    }

    /// Checks whether we have reached the `halt` label in kernel mode.
    fn at_halt(&self) -> bool {
        let halt = KERNEL.global_labels["halt"];
        let registers = self.get_registers();
        registers.is_kernel && (registers.program_counter == halt)
    }

    /// Returns the context in which the jumpdest analysis should end.
    fn get_halt_context(&self) -> Option<usize> {
        None
    }

    fn push_cpu(&mut self, val: CpuColumnsView<F>) {
        self.get_mut_generation_state().traces.cpu.push(val);
    }

    fn push_logic(&mut self, op: logic::Operation) {
        self.get_mut_generation_state().traces.logic_ops.push(op);
    }

    fn push_arithmetic(&mut self, op: arithmetic::Operation) {
        self.get_mut_generation_state()
            .traces
            .arithmetic_ops
            .push(op);
    }

    fn push_memory(&mut self, op: MemoryOp) {
        self.get_mut_generation_state().traces.memory_ops.push(op);
    }

    fn push_byte_packing(&mut self, op: BytePackingOp) {
        self.get_mut_generation_state()
            .traces
            .byte_packing_ops
            .push(op);
    }

    fn push_keccak(&mut self, input: [u64; keccak::keccak_stark::NUM_INPUTS], clock: usize) {
        self.get_mut_generation_state()
            .traces
            .keccak_inputs
            .push((input, clock));
    }

    fn push_keccak_bytes(&mut self, input: [u8; KECCAK_WIDTH_BYTES], clock: usize) {
        let chunks = input
            .chunks(size_of::<u64>())
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect_vec()
            .try_into()
            .unwrap();
        self.push_keccak(chunks, clock);
    }

    fn push_keccak_sponge(&mut self, op: KeccakSpongeOp) {
        self.get_mut_generation_state()
            .traces
            .keccak_sponge_ops
            .push(op);
    }

    /// Returns the content of a the `KernelGeneral` segment of a `State`.
    fn mem_get_kernel_content(&self) -> Vec<Option<U256>>;

    /// Applies a `State`'s operations since a checkpoint.
    fn apply_ops(&mut self, checkpoint: GenerationStateCheckpoint);

    /// Returns the offsets at which execution must halt
    fn get_halt_offsets(&self) -> Vec<usize>;

    fn update_interpreter_final_registers(&mut self, _final_registers: RegistersState) {}

    /// Returns all the memory from non-stale contexts.
    /// This is only necessary during segment data generation, hence the blanket
    /// impl returns a dummy value.
    fn get_active_memory(&self) -> Option<MemoryState> {
        None
    }

    /// Simulates the CPU. It only generates the traces if the `State` is a
    /// `GenerationState`.
    fn run_cpu(
        &mut self,
        max_cpu_len_log: Option<usize>,
    ) -> anyhow::Result<(RegistersState, Option<MemoryState>)>
    where
        Self: Transition<F>,
    {
        let halt_offsets = self.get_halt_offsets();

        let cycle_limit =
            max_cpu_len_log.map(|max_len_log| (1 << max_len_log) - NUM_EXTRA_CYCLES_AFTER);

        let mut final_registers = RegistersState::default();
        let mut running = true;
        let mut final_clock = 0;
        loop {
            let registers = self.get_registers();
            let pc = registers.program_counter;

            let halt_final = registers.is_kernel && halt_offsets.contains(&pc);
            if running && (self.at_halt() || self.at_end_segment(cycle_limit)) {
                running = false;
                final_registers = registers;

                // If `stack_len` is 0, `stack_top` still contains a residual value.
                if final_registers.stack_len == 0 {
                    final_registers.stack_top = 0.into();
                }
                // If we are in the interpreter, we need to set the final register values.
                self.update_interpreter_final_registers(final_registers);
                final_clock = self.get_clock();
                self.final_exception()?;
            }

            let opt_halt_context = self.get_halt_context();
            if registers.is_kernel && halt_final {
                if let Some(halt_context) = opt_halt_context {
                    if self.get_context() == halt_context {
                        // Only happens during jumpdest analysis, we don't care about the output.
                        return Ok((final_registers, None));
                    }
                } else {
                    if !running {
                        debug_assert!(self.get_clock() - final_clock == NUM_EXTRA_CYCLES_AFTER - 1);
                    }
                    let final_mem = self.get_active_memory();
                    #[cfg(not(test))]
                    self.log(
                        Level::Info,
                        format!("CPU halted after {} cycles", self.get_clock()),
                    );
                    return Ok((final_registers, final_mem));
                }
            }

            self.transition()?;
        }
    }

    fn handle_error(&mut self, err: ProgramError) -> anyhow::Result<()>
    where
        Self: Transition<F>,
        Self: Sized,
    {
        let exc_code: u8 = match err {
            ProgramError::OutOfGas => 0,
            ProgramError::InvalidOpcode => 1,
            ProgramError::StackUnderflow => 2,
            ProgramError::InvalidJumpDestination => 3,
            ProgramError::InvalidJumpiDestination => 4,
            ProgramError::StackOverflow => 5,
            _ => bail!("TODO: figure out what to do with this..."),
        };

        let checkpoint = self.checkpoint();

        let (row, _) = self.base_row();
        generate_exception(exc_code, self, row)
            .map_err(|e| anyhow!("Exception handling failed with error: {:?}", e))?;

        self.apply_ops(checkpoint);

        Ok(())
    }

    fn transition(&mut self) -> anyhow::Result<()>
    where
        Self: Transition<F>,
        Self: Sized,
    {
        let checkpoint = self.checkpoint();
        let result = self.try_perform_instruction();

        match result {
            Ok(op) => {
                self.apply_ops(checkpoint);

                if might_overflow_op(op) {
                    self.get_mut_registers().check_overflow = true;
                }

                Ok(())
            }
            Err(e) => {
                if self.get_registers().is_kernel {
                    let offset_name = KERNEL.offset_name(self.get_registers().program_counter);
                    bail!(
                        "{:?} in kernel at pc={}, stack={:?}, memory={:?}",
                        e,
                        offset_name,
                        self.get_stack(),
                        self.mem_get_kernel_content()
                            .iter()
                            .map(|c| c.unwrap_or_default())
                            .collect_vec(),
                    );
                }
                self.rollback(checkpoint);
                self.handle_error(e)
            }
        }
    }

    fn try_perform_instruction(&mut self) -> Result<Operation, ProgramError>;

    /// Row that has the correct values for system registers and the code
    /// channel, but is otherwise blank. It fulfills the constraints that
    /// are common to successful operations and the exception operation. It
    /// also returns the opcode
    fn base_row(&mut self) -> (CpuColumnsView<F>, u8) {
        let generation_state = self.get_mut_generation_state();
        let mut row: CpuColumnsView<F> = CpuColumnsView::default();
        row.clock = F::from_canonical_usize(generation_state.traces.clock() + 1);
        row.context = F::from_canonical_usize(generation_state.registers.context);
        row.program_counter = F::from_canonical_usize(generation_state.registers.program_counter);
        row.is_kernel_mode = F::from_bool(generation_state.registers.is_kernel);
        row.gas = F::from_canonical_u64(generation_state.registers.gas_used);
        row.stack_len = F::from_canonical_usize(generation_state.registers.stack_len);
        fill_channel_with_value(&mut row, 0, generation_state.registers.stack_top);

        let opcode = read_code_memory(generation_state, &mut row);
        (row, opcode)
    }

    /// Logs `msg` in `debug` mode.
    #[inline]
    fn log_debug(&self, msg: String) {
        log::debug!("{}", msg);
    }

    /// Logs `msg` at `level`.
    #[inline]
    fn log(&self, level: Level, msg: String) {
        log::log!(level, "{}", msg);
    }
}

#[derive(Debug, Default)]
pub struct GenerationState<F: Field> {
    pub(crate) inputs: TrimmedGenerationInputs,
    pub(crate) registers: RegistersState,
    pub(crate) memory: MemoryState,
    pub(crate) traces: Traces<F>,

    pub(crate) next_txn_index: usize,

    /// Memory used by stale contexts can be pruned so proving segments can be
    /// smaller.
    pub(crate) stale_contexts: Vec<usize>,

    /// Prover inputs containing RLP data, in reverse order so that the next
    /// input can be obtained via `pop()`.
    pub(crate) rlp_prover_inputs: Vec<U256>,

    pub(crate) withdrawal_prover_inputs: Vec<U256>,

    pub(crate) ger_prover_inputs: Vec<U256>,

    /// The state trie only stores state keys, which are hashes of addresses,
    /// but sometimes it is useful to see the actual addresses for
    /// debugging. Here we store the mapping for all known addresses.
    pub(crate) state_key_to_address: HashMap<H256, Address>,

    /// Prover inputs containing the result of a MODMUL operation, in
    /// little-endian order (so that inputs are obtained in big-endian order
    /// via `pop()`). Contains both the remainder and the quotient, in that
    /// order.
    pub(crate) bignum_modmul_result_limbs: Vec<U256>,

    /// Pointers, within the `TrieData` segment, of the three MPTs.
    pub(crate) trie_root_ptrs: TrieRootPtrs,

    /// A hash map where the key is a context in the user's code and the value
    /// is the set of jump destinations with its corresponding "proof". A
    /// "proof" for a jump destination is either 0 or an address i > 32 in
    /// the code (not necessarily pointing to an opcode) such that for every
    /// j in [i, i+32] it holds that code[j] < 0x7f - j + i.
    pub(crate) jumpdest_table: Option<HashMap<usize, Vec<usize>>>,
}

impl<F: Field> GenerationState<F> {
    fn preinitialize_linked_lists_and_txn_and_receipt_mpts(
        &mut self,
        trie_inputs: &TrieInputs,
    ) -> TrieRootPtrs {
        let (trie_roots_ptrs, state_leaves, storage_leaves, trie_data) =
            load_linked_lists_and_txn_and_receipt_mpts(trie_inputs)
                .expect("Invalid MPT data for preinitialization");

        self.memory.insert_preinitialized_segment(
            Segment::AccountsLinkedList,
            crate::witness::memory::MemorySegmentState {
                content: state_leaves,
            },
        );
        self.memory.insert_preinitialized_segment(
            Segment::StorageLinkedList,
            crate::witness::memory::MemorySegmentState {
                content: storage_leaves,
            },
        );
        self.memory.insert_preinitialized_segment(
            Segment::TrieData,
            crate::witness::memory::MemorySegmentState { content: trie_data },
        );

        trie_roots_ptrs
    }

    pub(crate) fn new(inputs: &GenerationInputs, kernel_code: &[u8]) -> Result<Self, ProgramError> {
        let rlp_prover_inputs = all_rlp_prover_inputs_reversed(&inputs.signed_txns);
        let withdrawal_prover_inputs = all_withdrawals_prover_inputs_reversed(&inputs.withdrawals);
        let ger_prover_inputs = all_ger_prover_inputs_reversed(&inputs.global_exit_roots);
        let bignum_modmul_result_limbs = Vec::new();

        let mut state = Self {
            inputs: inputs.trim(),
            registers: Default::default(),
            memory: MemoryState::new(kernel_code),
            traces: Traces::default(),
            next_txn_index: 0,
            stale_contexts: Vec::new(),
            rlp_prover_inputs,
            withdrawal_prover_inputs,
            ger_prover_inputs,
            state_key_to_address: HashMap::new(),
            bignum_modmul_result_limbs,
            trie_root_ptrs: TrieRootPtrs {
                state_root_ptr: Some(0),
                txn_root_ptr: 0,
                receipt_root_ptr: 0,
            },
            jumpdest_table: None,
        };
        let trie_root_ptrs =
            state.preinitialize_linked_lists_and_txn_and_receipt_mpts(&inputs.tries);

        state.trie_root_ptrs = trie_root_ptrs;
        Ok(state)
    }

    pub(crate) fn new_with_segment_data(
        trimmed_inputs: &TrimmedGenerationInputs,
        segment_data: &GenerationSegmentData,
    ) -> Result<Self, ProgramError> {
        let mut state = Self {
            inputs: trimmed_inputs.clone(),
            ..Default::default()
        };

        state.memory.preinitialized_segments = segment_data.memory.preinitialized_segments.clone();

        state.set_segment_data(segment_data);

        Ok(state)
    }

    /// Updates `program_counter`, and potentially adds some extra handling if
    /// we're jumping to a special location.
    pub(crate) fn jump_to(&mut self, dst: usize) -> Result<(), ProgramError> {
        self.registers.program_counter = dst;
        if self.stack().is_empty() {
            // We cannot observe anything as the stack is empty.
            return Ok(());
        }
        if dst == KERNEL.global_labels["observe_new_address"] {
            let tip_u256 = stack_peek(self, 0)?;
            let tip_h256 = H256::from_uint(&tip_u256);
            let tip_h160 = H160::from(tip_h256);
            self.observe_address(tip_h160);
        } else if dst == KERNEL.global_labels["observe_new_contract"] {
            let tip_u256 = stack_peek(self, 0)?;
            let tip_h256 = H256::from_uint(&tip_u256);
            self.observe_contract(tip_h256)?;
        }

        Ok(())
    }

    /// Observe the given address, so that we will be able to recognize the
    /// associated state key. This is just for debugging purposes.
    pub(crate) fn observe_address(&mut self, address: Address) {
        let state_key = keccak(address.0);
        self.state_key_to_address.insert(state_key, address);
    }

    /// Observe the given code hash and store the associated code.
    /// When called, the code corresponding to `codehash` should be stored in
    /// the return data.
    pub(crate) fn observe_contract(&mut self, codehash: H256) -> Result<(), ProgramError> {
        if self.inputs.contract_code.contains_key(&codehash) {
            return Ok(()); // Return early if the code hash has already been
                           // observed.
        }

        let ctx = self.registers.context;
        let returndata_offset = ContextMetadata::ReturndataSize.unscale();
        let returndata_size_addr =
            MemoryAddress::new(ctx, Segment::ContextMetadata, returndata_offset);
        let returndata_size = u256_to_usize(self.memory.get_with_init(returndata_size_addr))?;
        let code = self.memory.contexts[ctx].segments[Segment::Returndata.unscale()].content
            [..returndata_size]
            .iter()
            .map(|x| x.unwrap_or_default().low_u32() as u8)
            .collect::<Vec<_>>();
        debug_assert_eq!(keccak(&code), codehash);

        self.inputs.contract_code.insert(codehash, code);

        Ok(())
    }

    pub(crate) fn rollback(&mut self, checkpoint: GenerationStateCheckpoint) {
        self.registers = checkpoint.registers;
        self.traces.rollback(checkpoint.traces);
    }

    pub(crate) fn stack(&self) -> Vec<U256> {
        const MAX_TO_SHOW: usize = 10;
        (0..self.registers.stack_len.min(MAX_TO_SHOW))
            .map(|i| stack_peek(self, i).unwrap())
            .collect()
    }

    /// Clones everything but the traces.
    pub(crate) fn soft_clone(&self) -> GenerationState<F> {
        Self {
            inputs: self.inputs.clone(), // inputs have already been trimmed here
            registers: self.registers,
            memory: self.memory.clone(),
            traces: Traces::default(),
            next_txn_index: 0,
            stale_contexts: Vec::new(),
            rlp_prover_inputs: self.rlp_prover_inputs.clone(),
            state_key_to_address: self.state_key_to_address.clone(),
            bignum_modmul_result_limbs: self.bignum_modmul_result_limbs.clone(),
            withdrawal_prover_inputs: self.withdrawal_prover_inputs.clone(),
            ger_prover_inputs: self.ger_prover_inputs.clone(),
            trie_root_ptrs: TrieRootPtrs {
                state_root_ptr: Some(0),
                txn_root_ptr: 0,
                receipt_root_ptr: 0,
            },
            jumpdest_table: None,
        }
    }

    pub(crate) fn set_segment_data(&mut self, segment_data: &GenerationSegmentData) {
        self.bignum_modmul_result_limbs
            .clone_from(&segment_data.extra_data.bignum_modmul_result_limbs);
        self.rlp_prover_inputs
            .clone_from(&segment_data.extra_data.rlp_prover_inputs);
        self.withdrawal_prover_inputs
            .clone_from(&segment_data.extra_data.withdrawal_prover_inputs);
        self.ger_prover_inputs
            .clone_from(&segment_data.extra_data.ger_prover_inputs);
        self.trie_root_ptrs
            .clone_from(&segment_data.extra_data.trie_root_ptrs);
        self.jumpdest_table
            .clone_from(&segment_data.extra_data.jumpdest_table);
        self.next_txn_index = segment_data.extra_data.next_txn_index;
        self.registers = RegistersState {
            program_counter: self.registers.program_counter,
            is_kernel: self.registers.is_kernel,
            is_stack_top_read: false,
            check_overflow: false,
            ..segment_data.registers_before
        };
    }
}

impl<F: Field> State<F> for GenerationState<F> {
    fn checkpoint(&mut self) -> GenerationStateCheckpoint {
        GenerationStateCheckpoint {
            registers: self.registers,
            traces: self.traces.checkpoint(),
            clock: self.get_clock(),
        }
    }

    fn incr_gas(&mut self, n: u64) {
        self.registers.gas_used += n;
    }

    fn incr_pc(&mut self, n: usize) {
        self.registers.program_counter += n;
    }

    fn get_registers(&self) -> RegistersState {
        self.registers
    }

    fn get_mut_registers(&mut self) -> &mut RegistersState {
        &mut self.registers
    }

    fn get_from_memory(&mut self, address: MemoryAddress) -> U256 {
        self.memory.get_with_init(address)
    }

    fn get_generation_state(&self) -> &GenerationState<F> {
        self
    }

    fn get_mut_generation_state(&mut self) -> &mut GenerationState<F> {
        self
    }

    fn get_clock(&self) -> usize {
        self.traces.clock()
    }

    fn rollback(&mut self, checkpoint: GenerationStateCheckpoint) {
        self.rollback(checkpoint)
    }

    fn get_stack(&self) -> Vec<U256> {
        self.stack()
    }

    fn get_context(&self) -> usize {
        self.registers.context
    }

    fn mem_get_kernel_content(&self) -> Vec<Option<U256>> {
        self.memory.contexts[0].segments[Segment::KernelGeneral.unscale()]
            .content
            .clone()
    }

    fn apply_ops(&mut self, checkpoint: GenerationStateCheckpoint) {
        self.memory
            .apply_ops(self.traces.mem_ops_since(checkpoint.traces))
    }

    fn get_halt_offsets(&self) -> Vec<usize> {
        vec![KERNEL.global_labels["halt_final"]]
    }

    fn try_perform_instruction(&mut self) -> Result<Operation, ProgramError> {
        let registers = self.registers;
        let (mut row, opcode) = self.base_row();

        let op = decode(registers, opcode)?;

        if registers.is_kernel {
            log_kernel_instruction(self, op);
        } else {
            self.log_debug(format!("User instruction: {:?}", op));
        }
        fill_op_flag(op, &mut row);

        self.fill_stack_fields(&mut row)?;

        // Might write in general CPU columns when it shouldn't, but the correct values
        // will overwrite these ones during the op generation.
        if let Some(special_len) = get_op_special_length(op) {
            let special_len_f = F::from_canonical_usize(special_len);
            let diff = row.stack_len - special_len_f;
            if let Some(inv) = diff.try_inverse() {
                row.general.stack_mut().stack_inv = inv;
                row.general.stack_mut().stack_inv_aux = F::ONE;
                self.registers.is_stack_top_read = true;
            } else if self.stack().len() != special_len {
                // If the `State` is an interpreter, we cannot rely on the row to carry out the
                // check.
                self.registers.is_stack_top_read = true;
            }
        } else if let Some(inv) = row.stack_len.try_inverse() {
            row.general.stack_mut().stack_inv = inv;
            row.general.stack_mut().stack_inv_aux = F::ONE;
        }

        self.perform_state_op(op, row)
    }
}

impl<F: Field> Transition<F> for GenerationState<F> {
    fn skip_if_necessary(&mut self, op: Operation) -> Result<Operation, ProgramError> {
        Ok(op)
    }

    fn generate_jumpdest_analysis(&mut self, _dst: usize) -> bool {
        false
    }

    fn fill_stack_fields(&mut self, row: &mut CpuColumnsView<F>) -> Result<(), ProgramError> {
        if self.registers.is_stack_top_read {
            let channel = &mut row.mem_channels[0];
            channel.used = F::ONE;
            channel.is_read = F::ONE;
            channel.addr_context = F::from_canonical_usize(self.registers.context);
            channel.addr_segment = F::from_canonical_usize(Segment::Stack.unscale());
            channel.addr_virtual = F::from_canonical_usize(self.registers.stack_len - 1);

            let address = MemoryAddress::new(
                self.registers.context,
                Segment::Stack,
                self.registers.stack_len - 1,
            );

            let mem_op = MemoryOp::new(
                GeneralPurpose(0),
                self.traces.clock(),
                address,
                MemoryOpKind::Read,
                self.registers.stack_top,
            );
            self.push_memory(mem_op);
        }
        self.registers.is_stack_top_read = false;

        if self.registers.check_overflow {
            if self.registers.is_kernel {
                row.general.stack_mut().stack_len_bounds_aux = F::ZERO;
            } else {
                let clock = self.traces.clock();
                let last_row = &mut self.traces.cpu[clock - 1];
                let disallowed_len = F::from_canonical_usize(MAX_USER_STACK_SIZE + 1);
                let diff = row.stack_len - disallowed_len;
                if let Some(inv) = diff.try_inverse() {
                    last_row.general.stack_mut().stack_len_bounds_aux = inv;
                }
            }
        }
        self.registers.check_overflow = false;

        Ok(())
    }
}

pub(crate) struct GenerationStateCheckpoint {
    pub(crate) registers: RegistersState,
    pub(crate) traces: TraceCheckpoint,
    pub(crate) clock: usize,
}

/// Withdrawals prover input array is of the form `[addr0, amount0, ..., addrN,
/// amountN, U256::MAX, U256::MAX]`. Returns the reversed array.
pub(crate) fn all_withdrawals_prover_inputs_reversed(withdrawals: &[(Address, U256)]) -> Vec<U256> {
    let mut withdrawal_prover_inputs = withdrawals
        .iter()
        .flat_map(|w| [U256::from((w.0).0.as_slice()), w.1])
        .collect::<Vec<_>>();
    withdrawal_prover_inputs.push(U256::MAX);
    withdrawal_prover_inputs.push(U256::MAX);
    withdrawal_prover_inputs.reverse();
    withdrawal_prover_inputs
}

/// Global exit roots prover input array is of the form `[N, timestamp1,
/// root1,..., timestampN, rootN]`. Returns the reversed array.
pub(crate) fn all_ger_prover_inputs_reversed(global_exit_roots: &[(U256, H256)]) -> Vec<U256> {
    let mut ger_prover_inputs = vec![global_exit_roots.len().into()];
    ger_prover_inputs.extend(
        global_exit_roots
            .iter()
            .flat_map(|ger| [ger.0, ger.1.into_uint()]),
    );
    ger_prover_inputs.reverse();
    ger_prover_inputs
}
