//! `MemAfterStark` is used to store the final values in memory.
//! It is checked against `MemoryStark` through a CTL.
//! This is used to ensure a continuation of the memory when proving
//! multiple segments of a single full transaction proof.
//! As such, `MemoryAfterStark` doesn't have any constraints.
use std::borrow::Borrow;
use std::cmp::max;
use std::iter::{self, once, repeat};
use std::marker::PhantomData;
use std::mem::size_of;

use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2::util::transpose;
use plonky2_util::ceil_div_usize;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use starky::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use starky::lookup::{Column, Filter, Lookup};
use starky::stark::Stark;

use crate::all_stark::EvmStarkFrame;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::keccak_util::keccakf_u32s;
use crate::mem_after::columns::*;
use crate::witness::memory::MemoryAddress;

/// Creates the vector of `Columns` corresponding to:
/// - the propagated address (context, segment, virt),
/// - the value in u32 limbs.
pub(crate) fn ctl_data<F: Field>() -> Vec<Column<F>> {
    let mut res = Column::singles([ADDR_CONTEXT, ADDR_SEGMENT, ADDR_VIRTUAL]).collect_vec();
    res.extend(Column::singles((0..8).map(value_limb)));
    res
}

/// CTL filter for memory operations.
pub(crate) fn ctl_filter<F: Field>() -> Filter<F> {
    Filter::new_simple(Column::single(FILTER))
}

/// Structure representing the `MemAfter` STARK.
#[derive(Copy, Clone, Default)]
pub(crate) struct MemAfterStark<F, const D: usize> {
    f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> MemAfterStark<F, D> {
    pub(crate) fn generate_trace(
        &self,
        final_values: &[Vec<F>],
        timing: &mut TimingTree,
    ) -> Vec<PolynomialValues<F>> {
        // Set the trace to the `final_values` provided by `MemoryStark`.
        let mut rows = final_values.to_vec().clone();

        let num_rows = rows.len();
        let num_rows_padded = max(16, num_rows.next_power_of_two());
        for _ in num_rows..num_rows_padded {
            rows.push(vec![F::ZERO; NUM_COLUMNS]);
        }

        let cols = transpose(&rows);

        cols.into_iter()
            .map(|column| PolynomialValues::new(column))
            .collect()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for MemAfterStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize> = EvmStarkFrame<P, FE, NUM_COLUMNS>
    where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;

    type EvaluationFrameTarget = EvmStarkFrame<ExtensionTarget<D>, ExtensionTarget<D>, NUM_COLUMNS>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let local_values = vars.get_local_values();
        // The filter must be binary.
        let filter = local_values[FILTER];
        yield_constr.constraint(filter * (filter - P::ONES));
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let local_values = vars.get_local_values();
        // The filter must be binary.
        let filter = local_values[FILTER];
        let constr = builder.add_const_extension(filter, F::NEG_ONE);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    fn constraint_degree(&self) -> usize {
        3
    }

    fn requires_ctls(&self) -> bool {
        true
    }

    fn lookups(&self) -> Vec<Lookup<F>> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;

    use anyhow::Result;
    use itertools::Itertools;
    use keccak_hash::keccak;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::PrimeField64;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use starky::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};

    use crate::keccak_sponge::columns::KeccakSpongeColumnsView;
    use crate::keccak_sponge::keccak_sponge_stark::{KeccakSpongeOp, KeccakSpongeStark};
    use crate::mem_after::mem_after_stark::MemAfterStark;
    use crate::memory::segments::Segment;
    use crate::witness::memory::MemoryAddress;

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = MemAfterStark<F, D>;

        let stark = S::default();
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_stark_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = MemAfterStark<F, D>;

        let stark = S::default();
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }
}
