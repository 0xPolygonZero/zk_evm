use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::cpu::columns::CpuColumnsView;

/// Evaluates the constraints for the DUP and SWAP opcodes.
pub(crate) fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
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
    // Disable the partial channel.
    {
        let constr = builder.mul_extension(lv.op.incr, lv.partial_channel.used);
        yield_constr.constraint(builder, constr);
    }
}
