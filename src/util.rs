use ethereum_types::{H160, U256};
use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::util::transpose;

/// Construct an integer from its constituent bits (in little-endian order)
pub fn limb_from_bits_le<P: PackedField>(iter: impl IntoIterator<Item = P>) -> P {
    // TODO: This is technically wrong, as 1 << i won't be canonical for all fields...
    iter.into_iter()
        .enumerate()
        .map(|(i, bit)| bit * P::Scalar::from_canonical_u64(1 << i))
        .sum()
}

/// Construct an integer from its constituent bits (in little-endian order): recursive edition
pub fn limb_from_bits_le_recursive<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    iter: impl IntoIterator<Item = ExtensionTarget<D>>,
) -> ExtensionTarget<D> {
    iter.into_iter()
        .enumerate()
        .fold(builder.zero_extension(), |acc, (i, bit)| {
            // TODO: This is technically wrong, as 1 << i won't be canonical for all fields...
            builder.mul_const_add_extension(F::from_canonical_u64(1 << i), bit, acc)
        })
}

/// A helper function to transpose a row-wise trace and put it in the format that `prove` expects.
pub fn trace_rows_to_poly_values<F: Field, const COLUMNS: usize>(
    trace_rows: Vec<[F; COLUMNS]>,
) -> Vec<PolynomialValues<F>> {
    let trace_row_vecs = trace_rows.into_iter().map(|row| row.to_vec()).collect_vec();
    let trace_col_vecs: Vec<Vec<F>> = transpose(&trace_row_vecs);
    trace_col_vecs
        .into_iter()
        .map(|column| PolynomialValues::new(column))
        .collect()
}

/// Returns the 32-bit little-endian limbs of a `U256`.
pub(crate) fn u256_limbs<F: Field>(u256: U256) -> [F; 8] {
    u256.0
        .into_iter()
        .flat_map(|limb_64| {
            let lo = (limb_64 & 0xFFFFFFFF) as u32;
            let hi = (limb_64 >> 32) as u32;
            [lo, hi]
        })
        .map(F::from_canonical_u32)
        .collect_vec()
        .try_into()
        .unwrap()
}

/// Returns the 32-bit limbs of a `U160`.
pub(crate) fn h160_limbs<F: Field>(h160: H160) -> [F; 5] {
    h160.0
        .chunks(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .map(F::from_canonical_u32)
        .collect_vec()
        .try_into()
        .unwrap()
}
