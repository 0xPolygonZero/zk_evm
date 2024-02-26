use std::collections::HashMap;

use anyhow::bail;
use log::log_enabled;
use plonky2::field::types::Field;

use super::memory::{MemoryOp, MemoryOpKind};
use super::util::fill_channel_with_value;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::interpreter::InterpreterMemOpKind;
use crate::cpu::stack::{
    EQ_STACK_BEHAVIOR, IS_ZERO_STACK_BEHAVIOR, JUMPI_OP, JUMP_OP, MAX_USER_STACK_SIZE,
    MIGHT_OVERFLOW, STACK_BEHAVIORS,
};
use crate::generation::state::{GenerationState, GenerationStateCheckpoint};
use crate::generation::State;
use crate::memory::segments::Segment;
use crate::witness::errors::ProgramError;
use crate::witness::gas::gas_to_charge;
use crate::witness::memory::MemoryAddress;
use crate::witness::memory::MemoryChannel::GeneralPurpose;
use crate::witness::operation::*;
use crate::witness::state::RegistersState;
use crate::witness::util::mem_read_code_with_log_and_fill;
use crate::{arithmetic, logic};

fn read_code_memory<F: Field>(state: &mut GenerationState<F>, row: &mut CpuColumnsView<F>) -> u8 {
    let code_context = state.registers.code_context();
    row.code_context = F::from_canonical_usize(code_context);

    let address = MemoryAddress::new(code_context, Segment::Code, state.registers.program_counter);
    let (opcode, mem_log) =
        mem_read_code_with_log_and_fill(address, state, row, false, &HashMap::default());

    state.traces.push_memory(mem_log);

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
        (0x49, true) => Ok(Operation::ProverInput),
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

fn fill_op_flag<F: Field>(op: Operation, row: &mut CpuColumnsView<F>) {
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

fn perform_op<F: Field>(
    any_state: &mut State<F>,
    op: Operation,
    opcode: u8,
    row: CpuColumnsView<F>,
) -> Result<(), ProgramError> {
    let (op, is_interpreter, preinitialized_segments, is_jumpdest_analysis) = match any_state {
        State::Generation(state) => (op, false, HashMap::default(), false),
        State::Interpreter(interpreter) => {
            // Jumpdest analysis is performed natively by the interpreter and not
            // using the non-deterministic Kernel assembly code.
            let op = if interpreter.is_kernel()
                && interpreter.is_jumpdest_analysis
                && interpreter.generation_state.registers.program_counter
                    == KERNEL.global_labels["jumpdest_analysis"]
            {
                interpreter.generation_state.registers.program_counter =
                    KERNEL.global_labels["jumpdest_analysis_end"];
                interpreter
                    .generation_state
                    .set_jumpdest_bits(&interpreter.generation_state.get_current_code()?);
                let opcode = interpreter
                    .code()
                    .get(interpreter.generation_state.registers.program_counter)
                    .byte(0);

                decode(interpreter.generation_state.registers, opcode)?
            } else {
                op
            };
            (
                op,
                true,
                interpreter.preinitialized_segments.clone(),
                interpreter.is_jumpdest_analysis,
            )
        }
    };

    #[cfg(debug_assertions)]
    if !any_state.get_registers().is_kernel {
        log::debug!(
            "User instruction {:?}, stack = {:?}, ctx = {}",
            op,
            {
                let mut stack = any_state.get_stack();
                stack.reverse();
                stack
            },
            any_state.get_registers().context
        );
    }

    let state = any_state.get_mut_generation_state();
    match op {
        Operation::Push(n) => generate_push(n, state, row)?,
        Operation::Dup(n) => generate_dup(n, state, row)?,
        Operation::Swap(n) => generate_swap(n, state, row)?,
        Operation::Iszero => generate_iszero(state, row)?,
        Operation::Not => generate_not(state, row)?,
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shl) => generate_shl(state, row)?,
        Operation::BinaryArithmetic(arithmetic::BinaryOperator::Shr) => generate_shr(state, row)?,
        Operation::Syscall(opcode, stack_values_read, stack_len_increased) => {
            generate_syscall(opcode, stack_values_read, stack_len_increased, state, row)?
        }
        Operation::Eq => generate_eq(state, row)?,
        Operation::BinaryLogic(binary_logic_op) => {
            generate_binary_logic_op(binary_logic_op, state, row)?
        }
        Operation::BinaryArithmetic(op) => generate_binary_arithmetic_op(op, state, row)?,
        Operation::TernaryArithmetic(op) => generate_ternary_arithmetic_op(op, state, row)?,
        Operation::KeccakGeneral => {
            generate_keccak_general(state, row, is_interpreter, &preinitialized_segments)?
        }
        Operation::ProverInput => generate_prover_input(state, row)?,
        Operation::Pop => generate_pop(state, row)?,
        Operation::Jump => generate_jump(any_state, row, is_jumpdest_analysis)?,
        Operation::Jumpi => generate_jumpi(any_state, row, is_jumpdest_analysis)?,
        Operation::Pc => generate_pc(state, row)?,
        Operation::Jumpdest => generate_jumpdest(state, row)?,
        Operation::GetContext => generate_get_context(state, row)?,
        Operation::SetContext => generate_set_context(state, row)?,
        Operation::Mload32Bytes => {
            generate_mload_32bytes(state, row, is_interpreter, &preinitialized_segments)?
        }
        Operation::Mstore32Bytes(n) => generate_mstore_32bytes(n, state, row)?,
        Operation::ExitKernel => generate_exit_kernel(state, row)?,
        Operation::MloadGeneral => {
            generate_mload_general(state, row, is_interpreter, &preinitialized_segments)?
        }
        Operation::MstoreGeneral => generate_mstore_general(state, row)?,
    };
    match any_state {
        State::Generation(state) => {}
        State::Interpreter(interpreter) => {
            interpreter.clear_traces();
            interpreter.opcode_count[opcode as usize] += 1;
        }
    }
    Ok(())
}

fn perform_state_op<F: Field>(
    any_state: &mut State<F>,
    opcode: u8,
    op: Operation,
    row: CpuColumnsView<F>,
) -> Result<Operation, ProgramError> {
    perform_op(any_state, op, opcode, row)?;
    any_state.incr_pc(match op {
        Operation::Syscall(_, _, _) | Operation::ExitKernel => 0,
        Operation::Push(n) => n as usize + 1,
        Operation::Jump | Operation::Jumpi => 0,
        _ => 1,
    });

    any_state.incr_gas(gas_to_charge(op));
    let registers = any_state.get_registers();
    let gas_limit_address = MemoryAddress::new(
        registers.context,
        Segment::ContextMetadata,
        ContextMetadata::GasLimit.unscale(), // context offsets are already scaled
    );

    if !registers.is_kernel {
        let gas_limit = TryInto::<u64>::try_into(any_state.get_from_memory(gas_limit_address));
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

/// Row that has the correct values for system registers and the code channel,
/// but is otherwise blank. It fulfills the constraints that are common to
/// successful operations and the exception operation. It also returns the
/// opcode.
fn base_row<F: Field>(state: &mut GenerationState<F>) -> (CpuColumnsView<F>, u8) {
    let mut row: CpuColumnsView<F> = CpuColumnsView::default();
    row.clock = F::from_canonical_usize(state.traces.clock());
    row.context = F::from_canonical_usize(state.registers.context);
    row.program_counter = F::from_canonical_usize(state.registers.program_counter);
    row.is_kernel_mode = F::from_bool(state.registers.is_kernel);
    row.gas = F::from_canonical_u64(state.registers.gas_used);
    row.stack_len = F::from_canonical_usize(state.registers.stack_len);
    fill_channel_with_value(&mut row, 0, state.registers.stack_top);

    let opcode = read_code_memory(state, &mut row);
    (row, opcode)
}

pub(crate) fn fill_stack_fields<F: Field>(
    state: &mut GenerationState<F>,
    row: &mut CpuColumnsView<F>,
    is_generation: bool,
) -> Result<(), ProgramError> {
    if state.registers.is_stack_top_read && is_generation {
        let channel = &mut row.mem_channels[0];
        channel.used = F::ONE;
        channel.is_read = F::ONE;
        channel.addr_context = F::from_canonical_usize(state.registers.context);
        channel.addr_segment = F::from_canonical_usize(Segment::Stack.unscale());
        channel.addr_virtual = F::from_canonical_usize(state.registers.stack_len - 1);

        let address = MemoryAddress::new(
            state.registers.context,
            Segment::Stack,
            state.registers.stack_len - 1,
        );

        let mem_op = MemoryOp::new(
            GeneralPurpose(0),
            state.traces.clock(),
            address,
            MemoryOpKind::Read,
            state.registers.stack_top,
        );
        state.traces.push_memory(mem_op);
    }
    state.registers.is_stack_top_read = false;

    if state.registers.check_overflow && is_generation {
        if state.registers.is_kernel {
            row.general.stack_mut().stack_len_bounds_aux = F::ZERO;
        } else {
            let clock = state.traces.clock();
            // the clock starts at 1, so the last row is at index clock - 2.
            let last_row = &mut state.traces.cpu[clock - 2];
            let disallowed_len = F::from_canonical_usize(MAX_USER_STACK_SIZE + 1);
            let diff = row.stack_len - disallowed_len;
            if let Some(inv) = diff.try_inverse() {
                last_row.general.stack_mut().stack_len_bounds_aux = inv;
            } else {
                // This is a stack overflow that should have been caught earlier.
                return Err(ProgramError::InterpreterError);
            }
        }
    }
    state.registers.check_overflow = false;

    Ok(())
}

fn try_perform_instruction<F: Field>(any_state: &mut State<F>) -> Result<Operation, ProgramError> {
    let is_generation = any_state.is_generation_state();
    let registers = any_state.get_registers();

    let state = any_state.get_mut_generation_state();
    let (mut row, opcode) = base_row(state);

    let op = decode(registers, opcode)?;

    if registers.is_kernel {
        log_kernel_instruction(state, op);
    } else {
        log::debug!("User instruction: {:?}", op);
    }

    if is_generation {
        fill_op_flag(op, &mut row);
    }

    fill_stack_fields(state, &mut row, is_generation)?;

    // Might write in general CPU columns when it shouldn't, but the correct values
    // will overwrite these ones during the op generation.
    if let Some(special_len) = get_op_special_length(op) {
        let special_len_f = F::from_canonical_usize(special_len);
        let diff = row.stack_len - special_len_f;
        if let Some(inv) = diff.try_inverse()
            && is_generation
        {
            row.general.stack_mut().stack_inv = inv;
            row.general.stack_mut().stack_inv_aux = F::ONE;
            state.registers.is_stack_top_read = true;
        } else if !is_generation && (state.stack().len() != special_len) {
            // If the `State` is an interpreter, we cannot rely on the row to carry out the
            // check.
            state.registers.is_stack_top_read = true;
        }
    } else if let Some(inv) = row.stack_len.try_inverse() {
        row.general.stack_mut().stack_inv = inv;
        row.general.stack_mut().stack_inv_aux = F::ONE;
    }

    perform_state_op(any_state, opcode, op, row)
}

fn log_kernel_instruction<F: Field>(state: &GenerationState<F>, op: Operation) {
    // The logic below is a bit costly, so skip it if debug logs aren't enabled.
    if !log_enabled!(log::Level::Debug) {
        return;
    }

    let pc = state.registers.program_counter;
    let is_interesting_offset = KERNEL
        .offset_label(pc)
        .filter(|label| !label.starts_with("halt"))
        .is_some();
    let level = if is_interesting_offset {
        log::Level::Debug
    } else {
        log::Level::Trace
    };
    log::log!(
        level,
        "Cycle {}, ctx={}, pc={}, instruction={:?}, stack={:?}",
        state.traces.clock(),
        state.registers.context,
        KERNEL.offset_name(pc),
        op,
        state.stack(),
    );

    assert!(pc < KERNEL.code.len(), "Kernel PC is out of range: {}", pc);
}

pub(crate) fn final_exception<F: Field>(
    state: &mut State<F>,
    is_generation: bool,
) -> anyhow::Result<()> {
    let exc_code: u8 = 6;
    let checkpoint = state.checkpoint();

    let gen_state = state.get_mut_generation_state();

    let (row, _) = base_row(gen_state);
    if is_generation {
        println!(
            "entering exception with registers {:?}",
            gen_state.registers
        );
    }
    generate_exception(exc_code, gen_state, row, is_generation)
        .map_err(|_| anyhow::Error::msg("error handling errored..."))?;

    state.apply_ops(checkpoint);
    Ok(())
}

fn handle_error<F: Field>(any_state: &mut State<F>, err: ProgramError) -> anyhow::Result<()> {
    let exc_code: u8 = match err {
        ProgramError::OutOfGas => 0,
        ProgramError::InvalidOpcode => 1,
        ProgramError::StackUnderflow => 2,
        ProgramError::InvalidJumpDestination => 3,
        ProgramError::InvalidJumpiDestination => 4,
        ProgramError::StackOverflow => 5,
        _ => bail!("TODO: figure out what to do with this..."),
    };

    let (checkpoint, is_generation, state): (
        GenerationStateCheckpoint,
        bool,
        &mut GenerationState<_>,
    ) = match any_state {
        State::Generation(state) => (state.checkpoint(), true, state),
        State::Interpreter(interpreter) => (
            interpreter.checkpoint(),
            false,
            &mut interpreter.generation_state,
        ),
    };
    let (row, _) = base_row(state);
    generate_exception(exc_code, state, row, is_generation);
    match any_state {
        State::Generation(state) => {}
        // If we are in the interpreter, we do not need all the traces. We only need the memory
        // traces of the current operation.
        State::Interpreter(interpreter) => interpreter.clear_traces(),
    }
    any_state.apply_ops(checkpoint);

    Ok(())
}

pub(crate) fn transition<F: Field>(any_state: &mut State<F>) -> anyhow::Result<()> {
    let checkpoint = any_state.checkpoint();
    let result = try_perform_instruction(any_state);

    match result {
        Ok(op) => {
            any_state.apply_ops(checkpoint);

            if might_overflow_op(op) {
                any_state.get_mut_registers().check_overflow = true;
            }
            Ok(())
        }
        Err(e) => {
            if any_state.get_registers().is_kernel {
                let offset_name = KERNEL.offset_name(any_state.get_registers().program_counter);
                bail!(
                    "{:?} in kernel at pc={}, stack={:?}, memory={:?}",
                    e,
                    offset_name,
                    any_state.get_stack(),
                    any_state.mem_get_kernel_content(),
                );
            }
            any_state.rollback(checkpoint);
            handle_error(any_state, e)
        }
    }
}
