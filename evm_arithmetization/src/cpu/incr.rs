use itertools::izip;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::cpu::columns::{CpuColumnsView, MemoryChannelView};
use crate::memory::VALUE_LIMBS;

/// Constrain two channels such that their values `A` and `B` satisfy
/// `B = A + 1`, by using the `CpuIncrView` helper limbs.
fn channels_incremented_packed<P: PackedField>(
    filter: P,
    ch_a: &MemoryChannelView<P>,
    ch_b: &MemoryChannelView<P>,
    helper_limbs: [P; VALUE_LIMBS],
    yield_constr: &mut ConstraintConsumer<P>,
) {
    for (limb_a, limb_b, helper) in izip!(ch_a.value, ch_b.value, helper_limbs) {
        // If there was an overflow on the current limb, `limb_b` will be 0, else
        // we enforce proper increment.
        yield_constr.constraint(filter * limb_b * (limb_b - limb_a - helper));
    }
}

/// Constrain two channels such that their values `A` and `B` satisfy
/// `B = A + 1`, by using the `CpuIncrView` helper limbs.
fn channels_incremented_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    filter: ExtensionTarget<D>,
    ch_a: &MemoryChannelView<ExtensionTarget<D>>,
    ch_b: &MemoryChannelView<ExtensionTarget<D>>,
    helper_limbs: [ExtensionTarget<D>; VALUE_LIMBS],
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    for (limb_a, limb_b, helper) in izip!(ch_a.value, ch_b.value, helper_limbs) {
        // If there was an overflow on the current limb, `limb_b` will be 0, else
        // we enforce proper increment.
        let diff = builder.sub_extension(limb_b, limb_a);
        let diff = builder.sub_extension(diff, helper);
        let constr = builder.mul_extension(limb_b, diff);
        let constr = builder.mul_extension(filter, constr);
        yield_constr.constraint(builder, constr);
    }
}

/// Evaluates the constraints for the DUP and SWAP opcodes.
pub(crate) fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    // Constrain the helper columns.
    {
        // First limb is always 1.
        yield_constr.constraint(lv.op.incr * (lv.general.incr().limbs[0] - P::ONES));

        // 1s and 0s must be contiguous
        for i in 1..VALUE_LIMBS - 1 {
            yield_constr.constraint(
                lv.op.incr
                    * (lv.general.incr().limbs[i] - P::ONES)
                    * lv.general.incr().limbs[i + 1],
            );
        }
    }

    channels_incremented_packed(
        lv.op.incr,
        &lv.mem_channels[1],
        &lv.mem_channels[2],
        lv.general.incr().limbs,
        yield_constr,
    );

    // Disable the partial channel.
    yield_constr.constraint(lv.op.incr * lv.partial_channel.used);
}

/// Circuit version of `eval_packed`.
/// Evaluates the constraints for the DUP and SWAP opcodes.
pub(crate) fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    // Constrain the helper columns.
    {
        // First limb is always 1.
        let constr = builder.mul_sub_extension(lv.op.incr, lv.general.incr().limbs[0], lv.op.incr);
        yield_constr.constraint(builder, constr);

        // 1s and 0s must be contiguous
        for i in 1..VALUE_LIMBS - 1 {
            let constr =
                builder.mul_sub_extension(lv.op.incr, lv.general.incr().limbs[i], lv.op.incr);
            let constr = builder.mul_extension(constr, lv.general.incr().limbs[i + 1]);
            yield_constr.constraint(builder, constr);
        }
    }

    channels_incremented_circuit(
        builder,
        lv.op.incr,
        &lv.mem_channels[1],
        &lv.mem_channels[2],
        lv.general.incr().limbs,
        yield_constr,
    );

    // Disable the partial channel.
    {
        let constr = builder.mul_extension(lv.op.incr, lv.partial_channel.used);
        yield_constr.constraint(builder, constr);
    }
}
