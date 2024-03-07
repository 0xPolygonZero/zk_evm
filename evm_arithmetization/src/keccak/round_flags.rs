use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use starky::evaluation_frame::StarkEvaluationFrame;

use crate::all_stark::EvmStarkFrame;
use crate::keccak::columns::{reg_step, NUM_COLUMNS};
use crate::keccak::keccak_stark::NUM_ROUNDS;

pub(crate) fn eval_round_flags<F: Field, P: PackedField<Scalar = F>>(
    vars: &EvmStarkFrame<P, F, NUM_COLUMNS>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let local_values = vars.get_local_values();
    let next_values = vars.get_next_values();

    // Constrain the flags to be either 0 or 1.
    for i in 0..NUM_ROUNDS {
        let current_round_flag = local_values[reg_step(i)];
        yield_constr.constraint(current_round_flag * (current_round_flag - F::ONE));
    }

    // Initially, the first step flag should be 1 while the others should be 0.
    let local_any_flag = (0..NUM_ROUNDS)
        .map(|i| local_values[reg_step(i)])
        .sum::<P>();

    yield_constr.constraint_first_row(local_any_flag * (local_values[reg_step(0)] - F::ONE));
    for i in 1..NUM_ROUNDS {
        yield_constr.constraint_first_row(local_any_flag * local_values[reg_step(i)]);
    }

    // Flags should circularly increment, or be all zero for padding rows.
    let current_any_flag = (0..NUM_ROUNDS)
        .map(|i| local_values[reg_step(i)])
        .sum::<P>();
    let next_any_flag = (0..NUM_ROUNDS).map(|i| next_values[reg_step(i)]).sum::<P>();
    // Padding row should only start after the last round row.
    let last_round_flag = local_values[reg_step(NUM_ROUNDS - 1)];
    let padding_constraint =
        (next_any_flag - F::ONE) * current_any_flag * (last_round_flag - F::ONE);
    for i in 0..NUM_ROUNDS {
        let current_round_flag = local_values[reg_step(i)];
        let next_round_flag = next_values[reg_step((i + 1) % NUM_ROUNDS)];
        yield_constr.constraint_transition(
            next_any_flag * (next_round_flag - current_round_flag) + padding_constraint,
        );
    }

    // Padding rows should always be followed by padding rows.
    yield_constr.constraint_transition(next_any_flag * (current_any_flag - F::ONE));
}

pub(crate) fn eval_round_flags_recursively<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    vars: &EvmStarkFrame<ExtensionTarget<D>, ExtensionTarget<D>, NUM_COLUMNS>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let one = builder.one_extension();
    let local_values = vars.get_local_values();
    let next_values = vars.get_next_values();

    // Constrain the flags to be either 0 or 1.
    for i in 0..NUM_ROUNDS {
        let current_round_flag = local_values[reg_step(i)];
        let constraint =
            builder.mul_sub_extension(current_round_flag, current_round_flag, current_round_flag);
        yield_constr.constraint(builder, constraint);
    }

    // Initially, the first step flag should be 1 while the others should be 0.
    let local_any_flag =
        builder.add_many_extension((0..NUM_ROUNDS).map(|i| local_values[reg_step(i)]));
    // Initially, the first step flag should be 1 while the others should be 0.
    let step_0_minus_1 = builder.sub_extension(local_values[reg_step(0)], one);
    let step_0_minus_1 = builder.mul_extension(local_any_flag, step_0_minus_1);
    yield_constr.constraint_first_row(builder, step_0_minus_1);
    for i in 1..NUM_ROUNDS {
        let constr = builder.mul_extension(local_any_flag, local_values[reg_step(i)]);
        yield_constr.constraint_first_row(builder, constr);
    }

    // Flags should circularly increment, or be all zero for padding rows.
    let current_any_flag =
        builder.add_many_extension((0..NUM_ROUNDS).map(|i| local_values[reg_step(i)]));
    let next_any_flag =
        builder.add_many_extension((0..NUM_ROUNDS).map(|i| next_values[reg_step(i)]));
    // Padding row should only start after the last round row.
    let last_round_flag = local_values[reg_step(NUM_ROUNDS - 1)];
    let padding_constraint = {
        let tmp = builder.mul_sub_extension(current_any_flag, next_any_flag, current_any_flag);
        builder.mul_sub_extension(tmp, last_round_flag, tmp)
    };
    for i in 0..NUM_ROUNDS {
        let current_round_flag = local_values[reg_step(i)];
        let next_round_flag = next_values[reg_step((i + 1) % NUM_ROUNDS)];
        let flag_diff = builder.sub_extension(next_round_flag, current_round_flag);
        let constraint = builder.mul_add_extension(next_any_flag, flag_diff, padding_constraint);
        yield_constr.constraint_transition(builder, constraint);
    }

    // Padding rows should always be followed by padding rows.
    let constraint = builder.mul_sub_extension(next_any_flag, current_any_flag, next_any_flag);
    yield_constr.constraint_transition(builder, constraint);
}
