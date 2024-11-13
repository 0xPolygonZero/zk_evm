use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use super::dup_swap::{
    channels_equal_ext_circuit, channels_equal_packed, constrain_channel_ext_circuit,
    constrain_channel_packed,
};
use crate::cpu::columns::CpuColumnsView;

/// Evaluates the constraints for the INCR opcodes.
pub(crate) fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let base_filter = lv.op.incr;

    // Constrain the helper column
    yield_constr.constraint(
        base_filter
            * (lv.general.incr().is_not_incr1 - lv.opcode_bits[0])
            * (lv.general.incr().is_not_incr1 - lv.opcode_bits[1]),
    );

    let filter = base_filter * lv.general.incr().is_not_incr1;
    let filter_incr1 = base_filter * (lv.general.incr().is_not_incr1 - P::ONES);

    let n = lv.opcode_bits[0] + lv.opcode_bits[1] * P::Scalar::from_canonical_u64(2);

    // Disable the partial channel for all instructions.
    yield_constr.constraint(base_filter * lv.partial_channel.used);

    // Constrain the input channel's address, `is_read` and `used` fields.
    let read_channel = &lv.mem_channels[1];
    constrain_channel_packed(true, filter, n, read_channel, lv, yield_constr);

    // Constrain the output channel's address, `is_read` and `used` fields.
    let write_channel = &lv.mem_channels[2];
    constrain_channel_packed(false, filter, n, write_channel, lv, yield_constr);

    // Constrain the unchanged stack len for all instructions.
    yield_constr.constraint_transition(base_filter * (nv.stack_len - lv.stack_len));

    // Constrain the unchanged stack top for INCR2-INCR4.
    channels_equal_packed(
        filter,
        &lv.mem_channels[0],
        &nv.mem_channels[0],
        yield_constr,
    );

    // Disable regular read and write channels for INCR1.
    yield_constr.constraint(filter_incr1 * lv.mem_channels[1].used);
    yield_constr.constraint(filter_incr1 * lv.mem_channels[2].used);
}

/// Circuit version of `eval_packed`.
/// Evaluates the constraints for the INCR opcodes.
pub(crate) fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let base_filter = lv.op.incr;

    // Constrain the helper column
    {
        let diff_bit1 = builder.sub_extension(lv.general.incr().is_not_incr1, lv.opcode_bits[0]);
        let diff_bit2 = builder.sub_extension(lv.general.incr().is_not_incr1, lv.opcode_bits[1]);
        let constr = builder.mul_extension(base_filter, diff_bit1);
        let constr = builder.mul_extension(constr, diff_bit2);
        yield_constr.constraint(builder, constr);
    }

    let filter = builder.mul_extension(base_filter, lv.general.incr().is_not_incr1);
    let filter_incr1 =
        builder.mul_sub_extension(base_filter, lv.general.incr().is_not_incr1, base_filter);

    let n = lv.opcode_bits[..2].iter().enumerate().fold(
        builder.zero_extension(),
        |cumul, (i, &bit)| {
            builder.mul_const_add_extension(F::from_canonical_u64(1 << i), bit, cumul)
        },
    );

    // Disable the partial channel for all instructions.
    {
        let constr = builder.mul_extension(base_filter, lv.partial_channel.used);
        yield_constr.constraint(builder, constr);
    }

    // Constrain the input channel's address, `is_read` and `used` fields.
    let read_channel = &lv.mem_channels[1];
    constrain_channel_ext_circuit(builder, true, filter, n, read_channel, lv, yield_constr);

    // Constrain the output channel's address, `is_read` and `used` fields.
    let write_channel = &lv.mem_channels[2];
    constrain_channel_ext_circuit(builder, false, filter, n, write_channel, lv, yield_constr);

    // Constrain the unchanged stack len for all instructions.
    {
        let diff = builder.sub_extension(nv.stack_len, lv.stack_len);
        let constr = builder.mul_extension(base_filter, diff);
        yield_constr.constraint_transition(builder, constr);
    }

    // Constrain the unchanged stack top for INCR2-INCR4.
    channels_equal_ext_circuit(
        builder,
        filter,
        &lv.mem_channels[0],
        &nv.mem_channels[0],
        yield_constr,
    );

    // Disable regular read and write channels for INCR1.
    let constr = builder.mul_extension(filter_incr1, lv.mem_channels[1].used);
    yield_constr.constraint(builder, constr);
    let constr = builder.mul_extension(filter_incr1, lv.mem_channels[2].used);
    yield_constr.constraint(builder, constr);
}
