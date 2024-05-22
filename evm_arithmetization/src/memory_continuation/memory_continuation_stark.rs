//! `ContinuationMemoryStark` is used to store the initial or the final values
//! in memory. It is checked against `MemoryStark` through a CTL.
//! This is used to ensure a continuation of the memory when proving
//! multiple segments of a single full transaction proof.
//! As such, `ContinuationMemoryStark` doesn't have any constraints.
use std::cmp::max;
use std::marker::PhantomData;

use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::util::transpose;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use starky::evaluation_frame::StarkEvaluationFrame;
use starky::lookup::{Column, Filter, Lookup};
use starky::stark::Stark;

use super::columns::{value_limb, ADDR_CONTEXT, ADDR_SEGMENT, ADDR_VIRTUAL, FILTER, NUM_COLUMNS};
use crate::all_stark::EvmStarkFrame;
use crate::generation::MemBeforeValues;
use crate::memory::VALUE_LIMBS;

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

/// Creates the vector of `Columns` corresponding to:
/// - the initialized address (context, segment, virt),
/// - the value in u32 limbs.
pub(crate) fn ctl_data_memory<F: Field>() -> Vec<Column<F>> {
    let mut res = vec![Column::constant(F::ZERO)]; // IS_READ
    res.extend(Column::singles([ADDR_CONTEXT, ADDR_SEGMENT, ADDR_VIRTUAL]).collect_vec());
    res.extend(Column::singles((0..8).map(value_limb)));
    res.push(Column::constant(F::ZERO)); // TIMESTAMP
    res
}

/// Convert `mem_before_values` to a vector of memory trace rows
pub(crate) fn mem_before_values_to_rows<F: Field>(
    mem_before_values: &MemBeforeValues,
) -> Vec<Vec<F>> {
    mem_before_values
        .iter()
        .map(|mem_data| {
            let mut row = vec![F::ZERO; NUM_COLUMNS];
            row[FILTER] = F::ONE;
            row[ADDR_CONTEXT] = F::from_canonical_usize(mem_data.0.context);
            row[ADDR_SEGMENT] = F::from_canonical_usize(mem_data.0.segment);
            row[ADDR_VIRTUAL] = F::from_canonical_usize(mem_data.0.virt);
            for j in 0..VALUE_LIMBS {
                row[j + 4] = F::from_canonical_u32((mem_data.1 >> (j * 32)).low_u32());
            }
            row
        })
        .collect()
}

/// Structure representing the `ContinuationMemory` STARK.
#[derive(Copy, Clone, Default)]
pub(crate) struct MemoryContinuationStark<F, const D: usize> {
    f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> MemoryContinuationStark<F, D> {
    pub(crate) fn generate_trace(
        &self,
        propagated_values: Vec<Vec<F>>,
    ) -> Vec<PolynomialValues<F>> {
        // Set the trace to the `propagated_values` provided either by `MemoryStark`
        // (for final values) or the previous segment (for initial values).
        let mut rows = propagated_values;

        let num_rows = rows.len();
        let num_rows_padded = max(128, num_rows.next_power_of_two());
        for _ in num_rows..num_rows_padded {
            rows.push(vec![F::ZERO; NUM_COLUMNS]);
        }

        let cols = transpose(&rows);

        cols.into_iter()
            .map(|column| PolynomialValues::new(column))
            .collect()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for MemoryContinuationStark<F, D> {
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
    use anyhow::Result;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use starky::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};

    use crate::memory_continuation::memory_continuation_stark::MemoryContinuationStark;

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = MemoryContinuationStark<F, D>;

        let stark = S::default();
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_stark_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = MemoryContinuationStark<F, D>;

        let stark = S::default();
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }
}
