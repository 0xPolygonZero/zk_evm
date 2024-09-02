use ethereum_types::U256;
use log::log_enabled;
use plonky2::field::types::Field;

use super::util::{mem_read_gp_with_log_and_fill, stack_pop_with_log_and_fill};
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::cpu::stack::{
    EQ_STACK_BEHAVIOR, IS_ZERO_STACK_BEHAVIOR, JUMPI_OP, JUMP_OP, MIGHT_OVERFLOW, STACK_BEHAVIORS,
};
use crate::generation::state::State;
use crate::memory::segments::Segment;
use crate::witness::errors::ProgramError;
use crate::witness::gas::gas_to_charge;
use crate::witness::memory::MemoryAddress;
use crate::witness::operation::*;
use crate::witness::state::RegistersState;
use crate::witness::util::mem_read_code_with_log_and_fill;
use crate::{arithmetic, logic};

pub(crate) const EXC_STOP_CODE: u8 = 6;

pub(crate) fn read_code_memory<F: Field, T: Transition<F>>(
    state: &mut T,
    row: &mut CpuColumnsView<F>,
) -> u8 {
    let generation_state = state.get_mut_generation_state();
    let code_context = generation_state.registers.code_context();
    row.code_context = F::from_canonical_usize(code_context);

    let address = MemoryAddress::new(
        code_context,
        Segment::Code,
        generation_state.registers.program_counter,
    );
    let (opcode, mem_log) = mem_read_code_with_log_and_fill(address, generation_state, row);

    state.push_memory(mem_log);

    opcode
}

pub(crate) fn decode(registers: RegistersState, opcode: u8) -> Result<Operation, ProgramError> {
    match (opcode, registers.is_kernel) {
        (0x00, _) => Ok(Operation::Syscall(opcode, 0, false)), // STOP
        (0x01, _) => Ok(Operation::BinaryArithmetic(arithmetic::BinaryOperator::Add)),
        (0x02, _) => Ok(Operation::BinaryArithmetic(arithmetic::BinaryOperator::Mul)),
        (0x03, _) => Ok(Operation::BinaryArithmetic(arithmetic::BinaryOperator::Sub)),
        (0x04, _) => Ok(Operation::BinaryArithmetic(arithmetic::BinaryOperator::Div)),
        (0x05, _) => Ok(Operation::Syscall(opcode, 2, false)), // SDIV
        (0x06, _) => Ok(Operation::BinaryArithmetic(arithmetic::BinaryOperator::Mod)),
        (0x07, _) => Ok(Operation::Syscall(opcode, 2, false)), // SMOD
        (0x08, _) => Ok(Operation::TernaryArithmetic(
            arithmetic::TernaryOperator::AddMod,
        )),
        (0x09, _) => Ok(Operation::TernaryArithmetic(
            arithmetic::TernaryOperator::MulMod,
        )),
        (0x0a, _) => Ok(Operation::Syscall(opcode, 2, false)), // EXP
        (0x0b, _) => Ok(Operation::Syscall(opcode, 2, false)), // SIGNEXTEND
        (0x0c, true) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::AddFp254,
        )),
        (0x0d, true) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::MulFp254,
        )),
        (0x0e, true) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::SubFp254,
        )),
        (0x0f, true) => Ok(Operation::TernaryArithmetic(
            arithmetic::TernaryOperator::SubMod,
        )),
        (0x10, _) => Ok(Operation::BinaryArithmetic(arithmetic::BinaryOperator::Lt)),
        (0x11, _) => Ok(Operation::BinaryArithmetic(arithmetic::BinaryOperator::Gt)),
        (0x12, _) => Ok(Operation::Syscall(opcode, 2, false)), // SLT
        (0x13, _) => Ok(Operation::Syscall(opcode, 2, false)), // SGT
        (0x14, _) => Ok(Operation::Eq),
        (0x15, _) => Ok(Operation::Iszero),
        (0x16, _) => Ok(Operation::BinaryLogic(logic::Op::And)),
        (0x17, _) => Ok(Operation::BinaryLogic(logic::Op::Or)),
        (0x18, _) => Ok(Operation::BinaryLogic(logic::Op::Xor)),
        (0x19, _) => Ok(Operation::Not),
        (0x1a, _) => Ok(Operation::BinaryArithmetic(
            arithmetic::BinaryOperator::Byte,
        )),
        (0x1b, _) => Ok(Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shl)),
        (0x1c, _) => Ok(Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shr)),
        (0x1d, _) => Ok(Operation::Syscall(opcode, 2, false)), // SAR
        (0x20, _) => Ok(Operation::Syscall(opcode, 2, false)), // KECCAK256
        (0x21, true) => Ok(Operation::KeccakGeneral),
        (0x30, _) => Ok(Operation::Syscall(opcode, 0, true)), // ADDRESS
        (0x31, _) => Ok(Operation::Syscall(opcode, 1, false)), // BALANCE
        (0x32, _) => Ok(Operation::Syscall(opcode, 0, true)), // ORIGIN
        (0x33, _) => Ok(Operation::Syscall(opcode, 0, true)), // CALLER
        (0x34, _) => Ok(Operation::Syscall(opcode, 0, true)), // CALLVALUE
        (0x35, _) => Ok(Operation::Syscall(opcode, 1, false)), // CALLDATALOAD
        (0x36, _) => Ok(Operation::Syscall(opcode, 0, true)), // CALLDATASIZE
        (0x37, _) => Ok(Operation::Syscall(opcode, 3, false)), // CALLDATACOPY
        (0x38, _) => Ok(Operation::Syscall(opcode, 0, true)), // CODESIZE
        (0x39, _) => Ok(Operation::Syscall(opcode, 3, false)), // CODECOPY
        (0x3a, _) => Ok(Operation::Syscall(opcode, 0, true)), // GASPRICE
        (0x3b, _) => Ok(Operation::Syscall(opcode, 1, false)), // EXTCODESIZE
        (0x3c, _) => Ok(Operation::Syscall(opcode, 4, false)), // EXTCODECOPY
        (0x3d, _) => Ok(Operation::Syscall(opcode, 0, true)), // RETURNDATASIZE
        (0x3e, _) => Ok(Operation::Syscall(opcode, 3, false)), // RETURNDATACOPY
        (0x3f, _) => Ok(Operation::Syscall(opcode, 1, false)), // EXTCODEHASH
        (0x40, _) => Ok(Operation::Syscall(opcode, 1, false)), // BLOCKHASH
        (0x41, _) => Ok(Operation::Syscall(opcode, 0, true)), // COINBASE
        (0x42, _) => Ok(Operation::Syscall(opcode, 0, true)), // TIMESTAMP
        (0x43, _) => Ok(Operation::Syscall(opcode, 0, true)), // NUMBER
        (0x44, _) => Ok(Operation::Syscall(opcode, 0, true)), // DIFFICULTY
        (0x45, _) => Ok(Operation::Syscall(opcode, 0, true)), // GASLIMIT
        (0x46, _) => Ok(Operation::Syscall(opcode, 0, true)), // CHAINID
        (0x47, _) => Ok(Operation::Syscall(opcode, 0, true)), // SELFBALANCE
        (0x48, _) => Ok(Operation::Syscall(opcode, 0, true)), // BASEFEE
        (0x49, _) => Ok(Operation::Syscall(opcode, 1, false)), // BLOBHASH
        (0x4a, _) => Ok(Operation::Syscall(opcode, 0, true)), // BLOBBASEFEE
        (0x50, _) => Ok(Operation::Pop),
        (0x51, _) => Ok(Operation::Syscall(opcode, 1, false)), // MLOAD
        (0x52, _) => Ok(Operation::Syscall(opcode, 2, false)), // MSTORE
        (0x53, _) => Ok(Operation::Syscall(opcode, 2, false)), // MSTORE8
        (0x54, _) => Ok(Operation::Syscall(opcode, 1, false)), // SLOAD
        (0x55, _) => Ok(Operation::Syscall(opcode, 2, false)), // SSTORE
        (0x56, _) => Ok(Operation::Jump),
        (0x57, _) => Ok(Operation::Jumpi),
        (0x58, _) => Ok(Operation::Pc),
        (0x59, _) => Ok(Operation::Syscall(opcode, 0, true)), // MSIZE
        (0x5a, _) => Ok(Operation::Syscall(opcode, 0, true)), // GAS
        (0x5b, _) => Ok(Operation::Jumpdest),
        (0x5c, _) => Ok(Operation::Syscall(opcode, 1, false)), // TLOAD
        (0x5d, _) => Ok(Operation::Syscall(opcode, 2, false)), // TSTORE
        (0x5e, _) => Ok(Operation::Syscall(opcode, 3, false)), // MCOPY
        (0x5f..=0x7f, _) => Ok(Operation::Push(opcode - 0x5f)),
        (0x80..=0x8f, _) => Ok(Operation::Dup(opcode & 0xf)),
        (0x90..=0x9f, _) => Ok(Operation::Swap(opcode & 0xf)),
        (0xa0, _) => Ok(Operation::Syscall(opcode, 2, false)), // LOG0
        (0xa1, _) => Ok(Operation::Syscall(opcode, 3, false)), // LOG1
        (0xa2, _) => Ok(Operation::Syscall(opcode, 4, false)), // LOG2
        (0xa3, _) => Ok(Operation::Syscall(opcode, 5, false)), // LOG3
        (0xa4, _) => Ok(Operation::Syscall(opcode, 6, false)), // LOG4
        (0xa5, true) => {
            log::warn!(
                "Kernel panic at {}",
                KERNEL.offset_name(registers.program_counter),
            );
            Err(ProgramError::KernelPanic)
        }
        (0xc0..=0xdf, true) => Ok(Operation::Mstore32Bytes(opcode - 0xc0 + 1)),
        (0xee, true) => Ok(Operation::ProverInput),
        (0xf0, _) => Ok(Operation::Syscall(opcode, 3, false)), // CREATE
        (0xf1, _) => Ok(Operation::Syscall(opcode, 7, false)), // CALL
        (0xf2, _) => Ok(Operation::Syscall(opcode, 7, false)), // CALLCODE
        (0xf3, _) => Ok(Operation::Syscall(opcode, 2, false)), // RETURN
        (0xf4, _) => Ok(Operation::Syscall(opcode, 6, false)), // DELEGATECALL
        (0xf5, _) => Ok(Operation::Syscall(opcode, 4, false)), // CREATE2
        (0xf6, true) => Ok(Operation::GetContext),
        (0xf7, true) => Ok(Operation::SetContext),
        (0xf8, true) => Ok(Operation::Mload32Bytes),
        (0xf9, true) => Ok(Operation::ExitKernel),
        (0xfa, _) => Ok(Operation::Syscall(opcode, 6, false)), // STATICCALL
        (0xfb, true) => Ok(Operation::MloadGeneral),
        (0xfc, true) => Ok(Operation::MstoreGeneral),
        (0xfd, _) => Ok(Operation::Syscall(opcode, 2, false)), // REVERT
        (0xff, _) => Ok(Operation::Syscall(opcode, 1, false)), // SELFDESTRUCT
        _ => {
            log::warn!("Invalid opcode: {}", opcode);
            Err(ProgramError::InvalidOpcode)
        }
    }
}

pub(crate) fn fill_op_flag<F: Field>(op: Operation, row: &mut CpuColumnsView<F>) {
    let flags = &mut row.op;
    *match op {
        Operation::Dup(_) | Operation::Swap(_) => &mut flags.dup_swap,
        Operation::Iszero | Operation::Eq => &mut flags.eq_iszero,
        Operation::Not | Operation::Pop => &mut flags.not_pop,
        Operation::Syscall(_, _, _) => &mut flags.syscall,
        Operation::BinaryLogic(_) => &mut flags.logic_op,
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::AddFp254)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::MulFp254)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::SubFp254) => &mut flags.fp254_op,
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shl)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shr) => &mut flags.shift,
        Operation::BinaryArithmetic(_) => &mut flags.binary_op,
        Operation::TernaryArithmetic(_) => &mut flags.ternary_op,
        Operation::KeccakGeneral | Operation::Jumpdest => &mut flags.jumpdest_keccak_general,
        Operation::ProverInput | Operation::Push(1..) => &mut flags.push_prover_input,
        Operation::Jump | Operation::Jumpi => &mut flags.jumps,
        Operation::Pc | Operation::Push(0) => &mut flags.pc_push0,
        Operation::GetContext | Operation::SetContext => &mut flags.context_op,
        Operation::Mload32Bytes | Operation::Mstore32Bytes(_) => &mut flags.m_op_32bytes,
        Operation::ExitKernel => &mut flags.exit_kernel,
        Operation::MloadGeneral | Operation::MstoreGeneral => &mut flags.m_op_general,
    } = F::ONE;
}

// Equal to the number of pops if an operation pops without pushing, and `None`
// otherwise.
pub(crate) const fn get_op_special_length(op: Operation) -> Option<usize> {
    let behavior_opt = match op {
        Operation::Push(0) | Operation::Pc => STACK_BEHAVIORS.pc_push0,
        Operation::Push(1..) | Operation::ProverInput => STACK_BEHAVIORS.push_prover_input,
        Operation::Dup(_) | Operation::Swap(_) => STACK_BEHAVIORS.dup_swap,
        Operation::Iszero => IS_ZERO_STACK_BEHAVIOR,
        Operation::Not | Operation::Pop => STACK_BEHAVIORS.not_pop,
        Operation::Syscall(_, _, _) => STACK_BEHAVIORS.syscall,
        Operation::Eq => EQ_STACK_BEHAVIOR,
        Operation::BinaryLogic(_) => STACK_BEHAVIORS.logic_op,
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::AddFp254)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::MulFp254)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::SubFp254) => {
            STACK_BEHAVIORS.fp254_op
        }
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shl)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shr) => STACK_BEHAVIORS.shift,
        Operation::BinaryArithmetic(_) => STACK_BEHAVIORS.binary_op,
        Operation::TernaryArithmetic(_) => STACK_BEHAVIORS.ternary_op,
        Operation::KeccakGeneral | Operation::Jumpdest => STACK_BEHAVIORS.jumpdest_keccak_general,
        Operation::Jump => JUMP_OP,
        Operation::Jumpi => JUMPI_OP,
        Operation::GetContext | Operation::SetContext => None,
        Operation::Mload32Bytes | Operation::Mstore32Bytes(_) => STACK_BEHAVIORS.m_op_32bytes,
        Operation::ExitKernel => STACK_BEHAVIORS.exit_kernel,
        Operation::MloadGeneral | Operation::MstoreGeneral => STACK_BEHAVIORS.m_op_general,
    };
    if let Some(behavior) = behavior_opt {
        if behavior.num_pops > 0 && !behavior.pushes {
            Some(behavior.num_pops)
        } else {
            None
        }
    } else {
        None
    }
}

// These operations might trigger a stack overflow, typically those pushing
// without popping. Kernel-only pushing instructions aren't considered; they
// can't overflow.
pub(crate) const fn might_overflow_op(op: Operation) -> bool {
    match op {
        Operation::Push(1..) | Operation::ProverInput => MIGHT_OVERFLOW.push_prover_input,
        Operation::Dup(_) | Operation::Swap(_) => MIGHT_OVERFLOW.dup_swap,
        Operation::Iszero | Operation::Eq => MIGHT_OVERFLOW.eq_iszero,
        Operation::Not | Operation::Pop => MIGHT_OVERFLOW.not_pop,
        Operation::Syscall(_, _, _) => MIGHT_OVERFLOW.syscall,
        Operation::BinaryLogic(_) => MIGHT_OVERFLOW.logic_op,
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::AddFp254)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::MulFp254)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::SubFp254) => {
            MIGHT_OVERFLOW.fp254_op
        }
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shl)
        | Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shr) => MIGHT_OVERFLOW.shift,
        Operation::BinaryArithmetic(_) => MIGHT_OVERFLOW.binary_op,
        Operation::TernaryArithmetic(_) => MIGHT_OVERFLOW.ternary_op,
        Operation::KeccakGeneral | Operation::Jumpdest => MIGHT_OVERFLOW.jumpdest_keccak_general,
        Operation::Jump | Operation::Jumpi => MIGHT_OVERFLOW.jumps,
        Operation::Pc | Operation::Push(0) => MIGHT_OVERFLOW.pc_push0,
        Operation::GetContext | Operation::SetContext => MIGHT_OVERFLOW.context_op,
        Operation::Mload32Bytes | Operation::Mstore32Bytes(_) => MIGHT_OVERFLOW.m_op_32bytes,
        Operation::ExitKernel => MIGHT_OVERFLOW.exit_kernel,
        Operation::MloadGeneral | Operation::MstoreGeneral => MIGHT_OVERFLOW.m_op_general,
    }
}

pub(crate) fn log_kernel_instruction<F: Field, S: State<F>>(state: &mut S, op: Operation) {
    // The logic below is a bit costly, so skip it if debug logs aren't enabled.
    if !log_enabled!(log::Level::Debug) {
        return;
    }

    let pc = state.get_registers().program_counter;
    let is_interesting_offset = KERNEL
        .offset_label(pc)
        .filter(|label| !label.starts_with("halt"))
        .is_some();
    let level = if is_interesting_offset {
        log::Level::Debug
    } else {
        log::Level::Trace
    };
    state.log(
        level,
        format!(
            "Cycle {}, ctx={}, pc={}, instruction={:?}, stack={:?}",
            state.get_clock(),
            state.get_context(),
            KERNEL.offset_name(pc),
            op,
            state.get_generation_state().stack(),
        ),
    );

    assert!(pc < KERNEL.code.len(), "Kernel PC is out of range: {}", pc);
}

pub(crate) trait Transition<F: Field>: State<F>
where
    Self: Sized,
{
    /// When in jumpdest analysis, adds the offset `dst` to the jumpdest table.
    /// Returns a boolean indicating whether we are running the jumpdest
    /// analysis.
    fn generate_jumpdest_analysis(&mut self, dst: usize) -> bool;

    fn final_exception(&mut self) -> anyhow::Result<()> {
        let checkpoint = self.checkpoint();

        let (row, _) = self.base_row();

        generate_exception(EXC_STOP_CODE, self, row)
            .map_err(|e| anyhow::anyhow!("Exception handling failed with error {:?}", e))?;

        self.apply_ops(checkpoint);
        Ok(())
    }

    /// Performs the next operation in the execution, and updates the gas used
    /// and program counter.
    fn perform_state_op(
        &mut self,
        op: Operation,
        row: CpuColumnsView<F>,
    ) -> Result<Operation, ProgramError>
    where
        Self: Sized,
    {
        self.perform_op(op, row)?;
        self.incr_pc(match op {
            Operation::Syscall(_, _, _) | Operation::ExitKernel => 0,
            Operation::Push(n) => n as usize + 1,
            Operation::Jump | Operation::Jumpi => 0,
            _ => 1,
        });

        self.incr_gas(gas_to_charge(op));
        let registers = self.get_registers();
        let gas_limit_address = MemoryAddress::new(
            registers.context,
            Segment::ContextMetadata,
            ContextMetadata::GasLimit.unscale(), // context offsets are already scaled
        );

        if !registers.is_kernel {
            let gas_limit = TryInto::<u64>::try_into(self.get_from_memory(gas_limit_address));
            match gas_limit {
                Ok(limit) => {
                    if registers.gas_used > limit {
                        return Err(ProgramError::OutOfGas);
                    }
                }
                Err(_) => return Err(ProgramError::IntegerTooLarge),
            }
        }

        Ok(op)
    }

    fn generate_jump(&mut self, mut row: CpuColumnsView<F>) -> Result<(), ProgramError> {
        let [(dst, _)] =
            stack_pop_with_log_and_fill::<1, _>(self.get_mut_generation_state(), &mut row)?;

        let dst: u32 = dst
            .try_into()
            .map_err(|_| ProgramError::InvalidJumpDestination)?;

        if !self.generate_jumpdest_analysis(dst as usize) {
            let gen_state = self.get_mut_generation_state();
            let (jumpdest_bit, jumpdest_bit_log) = mem_read_gp_with_log_and_fill(
                NUM_GP_CHANNELS - 1,
                MemoryAddress::new(
                    gen_state.registers.context,
                    Segment::JumpdestBits,
                    dst as usize,
                ),
                gen_state,
                &mut row,
            );

            row.mem_channels[1].value[0] = F::ONE;

            if gen_state.registers.is_kernel {
                // Don't actually do the read, just set the address, etc.
                let channel = &mut row.mem_channels[NUM_GP_CHANNELS - 1];
                channel.used = F::ZERO;
                channel.value[0] = F::ONE;
            } else {
                if jumpdest_bit != U256::one() {
                    return Err(ProgramError::InvalidJumpDestination);
                }
                self.push_memory(jumpdest_bit_log);
            }

            // Extra fields required by the constraints.
            row.general.jumps_mut().should_jump = F::ONE;
            row.general.jumps_mut().cond_sum_pinv = F::ONE;

            let diff = row.stack_len - F::ONE;
            if let Some(inv) = diff.try_inverse() {
                row.general.stack_mut().stack_inv = inv;
                row.general.stack_mut().stack_inv_aux = F::ONE;
            } else {
                row.general.stack_mut().stack_inv = F::ZERO;
                row.general.stack_mut().stack_inv_aux = F::ZERO;
            }

            self.push_cpu(row);
        }
        self.get_mut_generation_state().jump_to(dst as usize)?;
        Ok(())
    }

    fn generate_jumpi(&mut self, mut row: CpuColumnsView<F>) -> Result<(), ProgramError> {
        let [(dst, _), (cond, log_cond)] =
            stack_pop_with_log_and_fill::<2, _>(self.get_mut_generation_state(), &mut row)?;

        let should_jump = !cond.is_zero();
        if should_jump {
            let dst: u32 = dst
                .try_into()
                .map_err(|_| ProgramError::InvalidJumpiDestination)?;
            if !self.generate_jumpdest_analysis(dst as usize) {
                row.general.jumps_mut().should_jump = F::ONE;
                let cond_sum_u64 = cond
                    .0
                    .into_iter()
                    .map(|limb| ((limb as u32) as u64) + (limb >> 32))
                    .sum();
                let cond_sum = F::from_canonical_u64(cond_sum_u64);
                row.general.jumps_mut().cond_sum_pinv = cond_sum.inverse();
            }
            self.get_mut_generation_state().jump_to(dst as usize)?;
        } else {
            row.general.jumps_mut().should_jump = F::ZERO;
            row.general.jumps_mut().cond_sum_pinv = F::ZERO;
            self.incr_pc(1);
        }

        let gen_state = self.get_mut_generation_state();
        let (jumpdest_bit, jumpdest_bit_log) = mem_read_gp_with_log_and_fill(
            NUM_GP_CHANNELS - 1,
            MemoryAddress::new(
                gen_state.registers.context,
                Segment::JumpdestBits,
                dst.low_u32() as usize,
            ),
            gen_state,
            &mut row,
        );
        if !should_jump || gen_state.registers.is_kernel {
            // Don't actually do the read, just set the address, etc.
            let channel = &mut row.mem_channels[NUM_GP_CHANNELS - 1];
            channel.used = F::ZERO;
            channel.value[0] = F::ONE;
        } else {
            if jumpdest_bit != U256::one() {
                return Err(ProgramError::InvalidJumpiDestination);
            }
            self.push_memory(jumpdest_bit_log);
        }

        let diff = row.stack_len - F::TWO;
        if let Some(inv) = diff.try_inverse() {
            row.general.stack_mut().stack_inv = inv;
            row.general.stack_mut().stack_inv_aux = F::ONE;
        } else {
            row.general.stack_mut().stack_inv = F::ZERO;
            row.general.stack_mut().stack_inv_aux = F::ZERO;
        }

        self.push_memory(log_cond);
        self.push_cpu(row);
        Ok(())
    }

    /// Skips the following instructions for some specific labels
    fn skip_if_necessary(&mut self, op: Operation) -> Result<Operation, ProgramError>;

    fn perform_op(&mut self, op: Operation, row: CpuColumnsView<F>) -> Result<(), ProgramError>
    where
        Self: Sized,
    {
        let op = self.skip_if_necessary(op)?;

        match op {
            Operation::Push(n) => generate_push(n, self, row),
            Operation::Dup(n) => generate_dup(n, self, row),
            Operation::Swap(n) => generate_swap(n, self, row),
            Operation::Iszero => generate_iszero(self, row),
            Operation::Not => generate_not(self, row),
            Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shl) => generate_shl(self, row),
            Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shr) => generate_shr(self, row),
            Operation::Syscall(opcode, stack_values_read, stack_len_increased) => {
                generate_syscall(opcode, stack_values_read, stack_len_increased, self, row)
            }
            Operation::Eq => generate_eq(self, row),
            Operation::BinaryLogic(binary_logic_op) => {
                generate_binary_logic_op(binary_logic_op, self, row)
            }
            Operation::BinaryArithmetic(op) => generate_binary_arithmetic_op(op, self, row),
            Operation::TernaryArithmetic(op) => generate_ternary_arithmetic_op(op, self, row),
            Operation::KeccakGeneral => generate_keccak_general(self, row),
            Operation::ProverInput => generate_prover_input(self, row),
            Operation::Pop => generate_pop(self, row),
            Operation::Jump => self.generate_jump(row),
            Operation::Jumpi => self.generate_jumpi(row),
            Operation::Pc => generate_pc(self, row),
            Operation::Jumpdest => generate_jumpdest(self, row),
            Operation::GetContext => generate_get_context(self, row),
            Operation::SetContext => generate_set_context(self, row),
            Operation::Mload32Bytes => generate_mload_32bytes(self, row),
            Operation::Mstore32Bytes(n) => generate_mstore_32bytes(n, self, row),
            Operation::ExitKernel => generate_exit_kernel(self, row),
            Operation::MloadGeneral => generate_mload_general(self, row),
            Operation::MstoreGeneral => generate_mstore_general(self, row),
        }
    }

    fn fill_stack_fields(&mut self, row: &mut CpuColumnsView<F>) -> Result<(), ProgramError>;
}
