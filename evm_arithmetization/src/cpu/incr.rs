use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use super::dup_swap::{constrain_channel_ext_circuit, constrain_channel_packed};
use crate::cpu::columns::CpuColumnsView;

/// Evaluates the constraints for the DUP and SWAP opcodes.
pub(crate) fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.incr;

    let n = lv.opcode_bits[0]
        + lv.opcode_bits[1] * P::Scalar::from_canonical_u64(2)
        + lv.opcode_bits[2] * P::Scalar::from_canonical_u64(4);

    // Disable the partial channel.
    yield_constr.constraint(lv.op.incr * lv.partial_channel.used);

    // Constrain the input channel's address, `is_read` and `used` fields.
    let read_channel = &lv.mem_channels[1];
    constrain_channel_packed(true, filter, n, read_channel, lv, yield_constr);

    // Constrain the output channel's address, `is_read` and `used` fields.
    let write_channel = &lv.mem_channels[2];
    constrain_channel_packed(false, filter, n, write_channel, lv, yield_constr);

    // Constrain the unchanged stack len.
    yield_constr.constraint_transition(filter * (nv.stack_len - lv.stack_len));
}

/// Circuit version of `eval_packed`.
/// Evaluates the constraints for the DUP and SWAP opcodes.
pub(crate) fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = lv.op.incr;

    let n = lv.opcode_bits[..3].iter().enumerate().fold(
        builder.zero_extension(),
        |cumul, (i, &bit)| {
            builder.mul_const_add_extension(F::from_canonical_u64(1 << i), bit, cumul)
        },
    );

    // Disable the partial channel.
    {
        let constr = builder.mul_extension(lv.op.incr, lv.partial_channel.used);
        yield_constr.constraint(builder, constr);
    }

    // Constrain the input channel's address, `is_read` and `used` fields.
    let read_channel = &lv.mem_channels[1];
    constrain_channel_ext_circuit(builder, true, filter, n, read_channel, lv, yield_constr);

    // Constrain the output channel's address, `is_read` and `used` fields.
    let write_channel = &lv.mem_channels[2];
    constrain_channel_ext_circuit(builder, false, filter, n, write_channel, lv, yield_constr);

    // Constrain the unchanged stack len.
    {
        let diff = builder.sub_extension(nv.stack_len, lv.stack_len);
        let constr = builder.mul_extension(filter, diff);
        yield_constr.constraint_transition(builder, constr);
    }
}
