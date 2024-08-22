use core::borrow::Borrow;
use core::marker::PhantomData;

use ethereum_types::U256;
use itertools::izip;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use starky::evaluation_frame::StarkEvaluationFrame;
use starky::lookup::{Column, Filter};
use starky::stark::Stark;
use starky::util::trace_rows_to_poly_values;

use crate::all_stark::EvmStarkFrame;
use crate::logic::columns::{LogicColumnsView, LOGIC_COL_MAP, NUM_COLUMNS};
use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive};

/// Total number of bits per input/output.
const VAL_BITS: usize = 256;
/// Number of bits stored per field element. Ensure that this fits; it is not
/// checked.
pub(crate) const PACKED_LIMB_BITS: usize = 32;
/// Number of field elements needed to store each input/output at the specified
/// packing.
const PACKED_LEN: usize = VAL_BITS.div_ceil(PACKED_LIMB_BITS);

/// `LogicStark` columns.
pub(crate) mod columns {
    use core::mem::transmute;

    use zk_evm_proc_macro::{Columns, DerefColumns};

    use super::{PACKED_LEN, VAL_BITS};
    use crate::util::indices_arr;

    /// Flag columns for the operation to perform.
    #[repr(C)]
    #[derive(DerefColumns, Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct OpsColumnsView<T> {
        /// 1 if this is an AND operation, 0 otherwise.
        pub is_and: T,
        /// 1 if this is an OR operation, 0 otherwise.
        pub is_or: T,
        /// 1 if this is a XOR operation, 0 otherwise.
        pub is_xor: T,
    }

    /// Columns for the `LogicStark`.
    #[repr(C)]
    #[derive(Columns, Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct LogicColumnsView<T> {
        /// The operation to perform.
        pub op: OpsColumnsView<T>,
        /// First input, decomposed into bits.
        pub input0: [T; VAL_BITS],
        /// Second input, decomposed into bits.
        pub input1: [T; VAL_BITS],
        /// The result is packed in limbs of `PACKED_LIMB_BITS` bits.
        pub result: [T; PACKED_LEN],
    }

    /// Total number of columns in `LogicStark`.
    /// `u8` is guaranteed to have a `size_of` of 1.
    pub(crate) const NUM_COLUMNS: usize = core::mem::size_of::<LogicColumnsView<u8>>();

    /// Mapping between [0..NUM_COLUMNS-1] and the logic columns.
    pub(crate) const LOGIC_COL_MAP: LogicColumnsView<usize> = make_col_map();

    const fn make_col_map() -> LogicColumnsView<usize> {
        let indices_arr = indices_arr::<NUM_COLUMNS>();
        unsafe { transmute::<[usize; NUM_COLUMNS], LogicColumnsView<usize>>(indices_arr) }
    }
}

/// Creates the vector of `Columns` corresponding to the opcode, the two inputs
/// and the output of the logic operation.
pub(crate) fn ctl_data<F: Field>() -> Vec<Column<F>> {
    // We scale each filter flag with the associated opcode value.
    // If a logic operation is happening on the CPU side, the CTL
    // will enforce that the reconstructed opcode value from the
    // opcode bits matches.
    let mut res = vec![Column::linear_combination([
        (LOGIC_COL_MAP.op.is_and, F::from_canonical_u8(0x16)),
        (LOGIC_COL_MAP.op.is_or, F::from_canonical_u8(0x17)),
        (LOGIC_COL_MAP.op.is_xor, F::from_canonical_u8(0x18)),
    ])];
    res.extend(
        LOGIC_COL_MAP
            .input0
            .chunks(PACKED_LIMB_BITS)
            .map(Column::le_bits),
    );
    res.extend(
        LOGIC_COL_MAP
            .input1
            .chunks(PACKED_LIMB_BITS)
            .map(Column::le_bits),
    );
    res.extend(LOGIC_COL_MAP.result.map(Column::single));
    res
}

/// CTL filter for logic operations.
pub(crate) fn ctl_filter<F: Field>() -> Filter<F> {
    Filter::new_simple(Column::sum(*LOGIC_COL_MAP.op))
}

/// Structure representing the Logic STARK, which computes all logic operations.
#[derive(Copy, Clone, Default)]
pub(crate) struct LogicStark<F, const D: usize> {
    pub f: PhantomData<F>,
}

/// Logic operations.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Op {
    And,
    Or,
    Xor,
}

impl Op {
    /// Returns the output of the current Logic operation.
    pub(crate) fn result(&self, a: U256, b: U256) -> U256 {
        match self {
            Op::And => a & b,
            Op::Or => a | b,
            Op::Xor => a ^ b,
        }
    }
}

/// A logic operation over `U256`` words. It contains an operator,
/// either `AND`, `OR` or `XOR`, two inputs and its expected result.
#[derive(Debug)]
pub(crate) struct Operation {
    operator: Op,
    input0: U256,
    input1: U256,
    pub(crate) result: U256,
}

impl Operation {
    /// Computes the expected result of an operator with the two provided
    /// inputs, and returns the associated logic `Operation`.
    pub(crate) fn new(operator: Op, input0: U256, input1: U256) -> Self {
        let result = operator.result(input0, input1);
        Operation {
            operator,
            input0,
            input1,
            result,
        }
    }

    /// Given an `Operation`, fills a row with the corresponding flag, inputs
    /// and output.
    fn into_row<F: Field>(self) -> [F; NUM_COLUMNS] {
        let Operation {
            operator,
            input0,
            input1,
            result,
        } = self;
        let mut row = [F::ZERO; NUM_COLUMNS];
        row[match operator {
            Op::And => LOGIC_COL_MAP.op.is_and,
            Op::Or => LOGIC_COL_MAP.op.is_or,
            Op::Xor => LOGIC_COL_MAP.op.is_xor,
        }] = F::ONE;
        for i in 0..256 {
            row[LOGIC_COL_MAP.input0[i]] = F::from_bool(input0.bit(i));
            row[LOGIC_COL_MAP.input1[i]] = F::from_bool(input1.bit(i));
        }
        let result_limbs: &[u64] = result.as_ref();
        for (i, &limb) in result_limbs.iter().enumerate() {
            row[LOGIC_COL_MAP.result[2 * i]] = F::from_canonical_u32(limb as u32);
            row[LOGIC_COL_MAP.result[2 * i + 1]] = F::from_canonical_u32((limb >> 32) as u32);
        }
        row
    }
}

impl<F: RichField, const D: usize> LogicStark<F, D> {
    /// Generates the trace polynomials for `LogicStark`.
    pub(crate) fn generate_trace(
        &self,
        operations: Vec<Operation>,
        min_rows: usize,
        timing: &mut TimingTree,
    ) -> Vec<PolynomialValues<F>> {
        // First, turn all provided operations into rows in `LogicStark`, and pad if
        // necessary.
        let trace_rows = timed!(
            timing,
            "generate trace rows",
            self.generate_trace_rows(operations, min_rows)
        );
        // Generate the trace polynomials from the trace values.
        let trace_polys = timed!(
            timing,
            "convert to PolynomialValues",
            trace_rows_to_poly_values(trace_rows)
        );
        trace_polys
    }

    /// Generate the `LogicStark` traces based on the provided vector of
    /// operations. The trace is padded to a power of two with all-zero
    /// rows.
    fn generate_trace_rows(
        &self,
        operations: Vec<Operation>,
        min_rows: usize,
    ) -> Vec<[F; NUM_COLUMNS]> {
        let len = operations.len();
        let padded_len = len.max(min_rows).next_power_of_two();

        let mut rows = Vec::with_capacity(padded_len);
        for op in operations {
            rows.push(op.into_row());
        }

        // Pad to a power of two.
        for _ in len..padded_len {
            rows.push([F::ZERO; NUM_COLUMNS]);
        }

        rows
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for LogicStark<F, D> {
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
        let lv: &[P; NUM_COLUMNS] = vars.get_local_values().try_into().unwrap();
        let lv: &LogicColumnsView<P> = lv.borrow();

        let is_and = lv.op.is_and;
        let is_or = lv.op.is_or;
        let is_xor = lv.op.is_xor;

        // Flags must be boolean.
        for &flag in &[is_and, is_or, is_xor] {
            yield_constr.constraint(flag * (flag - P::ONES));
        }

        // Only a single flag must be activated at once.
        let all_flags = is_and + is_or + is_xor;
        yield_constr.constraint(all_flags * (all_flags - P::ONES));

        // The result will be `in0 OP in1 = sum_coeff * (in0 + in1) + and_coeff * (in0
        // AND in1)`. `AND => sum_coeff = 0, and_coeff = 1`
        // `OR  => sum_coeff = 1, and_coeff = -1`
        // `XOR => sum_coeff = 1, and_coeff = -2`
        let sum_coeff = is_or + is_xor;
        let and_coeff = is_and - is_or - is_xor * FE::TWO;

        // Ensure that all bits are indeed bits.
        for input_bits in [lv.input0, lv.input1] {
            for bit in input_bits {
                yield_constr.constraint(bit * (bit - P::ONES));
            }
        }

        // Form the result
        for (result_limb, x_bits, y_bits) in izip!(
            lv.result,
            lv.input0.chunks(PACKED_LIMB_BITS),
            lv.input1.chunks(PACKED_LIMB_BITS),
        ) {
            let x: P = limb_from_bits_le(x_bits.iter().copied());
            let y: P = limb_from_bits_le(y_bits.iter().copied());

            let x_land_y: P = izip!(0.., x_bits, y_bits)
                .map(|(i, &x_bit, &y_bit)| x_bit * y_bit * FE::from_canonical_u64(1 << i))
                .sum();
            let x_op_y = sum_coeff * (x + y) + and_coeff * x_land_y;

            yield_constr.constraint(result_limb - x_op_y);
        }
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let lv: &[ExtensionTarget<D>; NUM_COLUMNS] = vars.get_local_values().try_into().unwrap();
        let lv: &LogicColumnsView<ExtensionTarget<D>> = lv.borrow();

        let is_and = lv.op.is_and;
        let is_or = lv.op.is_or;
        let is_xor = lv.op.is_xor;

        // Flags must be boolean.
        for &flag in &[is_and, is_or, is_xor] {
            let constraint = builder.mul_sub_extension(flag, flag, flag);
            yield_constr.constraint(builder, constraint);
        }

        // Only a single flag must be activated at once.
        let all_flags = builder.add_many_extension([is_and, is_or, is_xor]);
        let constraint = builder.mul_sub_extension(all_flags, all_flags, all_flags);
        yield_constr.constraint(builder, constraint);

        // The result will be `in0 OP in1 = sum_coeff * (in0 + in1) + and_coeff * (in0
        // AND in1)`. `AND => sum_coeff = 0, and_coeff = 1`
        // `OR  => sum_coeff = 1, and_coeff = -1`
        // `XOR => sum_coeff = 1, and_coeff = -2`
        let sum_coeff = builder.add_extension(is_or, is_xor);
        let and_coeff = {
            let and_coeff = builder.sub_extension(is_and, is_or);
            builder.mul_const_add_extension(-F::TWO, is_xor, and_coeff)
        };

        // Ensure that all bits are indeed bits.
        for input_bits in [lv.input0, lv.input1] {
            for bit in input_bits {
                let constr = builder.mul_sub_extension(bit, bit, bit);
                yield_constr.constraint(builder, constr);
            }
        }

        // Form the result
        for (result_limb, x_bits, y_bits) in izip!(
            lv.result,
            lv.input0.chunks(PACKED_LIMB_BITS),
            lv.input1.chunks(PACKED_LIMB_BITS),
        ) {
            let x = limb_from_bits_le_recursive(builder, x_bits.iter().copied());
            let y = limb_from_bits_le_recursive(builder, y_bits.iter().copied());

            let x_land_y = izip!(0usize.., x_bits, y_bits).fold(
                builder.zero_extension(),
                |acc, (i, &x_bit, &y_bit)| {
                    builder.arithmetic_extension(
                        F::from_canonical_u64(1 << i),
                        F::ONE,
                        x_bit,
                        y_bit,
                        acc,
                    )
                },
            );
            let x_op_y = {
                let x_op_y = builder.mul_extension(sum_coeff, x);
                let x_op_y = builder.mul_add_extension(sum_coeff, y, x_op_y);
                builder.mul_add_extension(and_coeff, x_land_y, x_op_y)
            };
            let constr = builder.sub_extension(result_limb, x_op_y);
            yield_constr.constraint(builder, constr);
        }
    }

    fn constraint_degree(&self) -> usize {
        3
    }

    fn requires_ctls(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use itertools::Itertools;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use starky::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};

    use super::*;
    use crate::logic::LogicStark;

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = LogicStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_stark_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = LogicStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    #[test]
    fn test_generate_eval_consistency() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = LogicStark<F, D>;

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);
        const N_ITERS: usize = 1000;

        for _ in 0..N_ITERS {
            for op in [Op::And, Op::Or, Op::Xor] {
                // Generate a trace row from an operation on random values.
                let operation = Operation::new(op, U256(rng.gen()), U256(rng.gen()));
                let expected = operation.result;
                let row = operation.into_row::<F>();
                let lv = EvmStarkFrame::from_values(&row, &[F::ZERO; NUM_COLUMNS], &[]);

                let stark = S::default();
                let mut constraint_consumer = ConstraintConsumer::new(
                    vec![GoldilocksField(2), GoldilocksField(3), GoldilocksField(5)],
                    F::ONE,
                    F::ONE,
                    F::ONE,
                );

                // Evaluate constraints.
                stark.eval_packed_generic(&lv, &mut constraint_consumer);
                for acc in constraint_consumer.accumulators() {
                    assert_eq!(acc, F::ZERO);
                }

                // Split each expected U256 limb into two.
                let expected_limbs = expected.as_ref().iter().flat_map(|&limb| {
                    [
                        F::from_canonical_u32(limb as u32),
                        F::from_canonical_u32((limb >> 32) as u32),
                    ]
                });

                // Check that the result limbs match the expected limbs.
                assert!(expected_limbs
                    .zip_eq(&row[LOGIC_COL_MAP.result[0]..])
                    .all(|(x, &y)| x == y));
            }
        }
    }
}
