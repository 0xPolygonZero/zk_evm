// In the context of continuations, we subdivide proofs into segments. To pass
// the necessary memory values from one segment to the next, we write those
// initial values at timestamp 0. For this reason, the clock has to be
// initialized to 1 at the start of a segment execution.

use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::cpu::columns::CpuColumnsView;

/// Check the correct updating of `clock`.
pub(crate) fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    // The clock is 1 at the beginning.
    yield_constr.constraint_first_row(lv.clock - P::ONES);
    // The clock is incremented by 1 at each row.
    yield_constr.constraint_transition(nv.clock - lv.clock - P::ONES);
}

/// Circuit version of `eval_packed`.
/// Check the correct updating of `clock`.
pub(crate) fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let first_clock = builder.add_const_extension(lv.clock, F::NEG_ONE);
    // The clock is 1 at the beginning.
    yield_constr.constraint_first_row(builder, first_clock);
    // The clock is incremented by 1 at each row.
    {
        let new_clock = builder.add_const_extension(lv.clock, F::ONE);
        let constr = builder.sub_extension(nv.clock, new_clock);
        yield_constr.constraint_transition(builder, constr);
    }
}
