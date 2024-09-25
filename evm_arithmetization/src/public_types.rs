use mpt_trie::partial_trie::HashedPartialTrie;
use plonky2::hash::hash_types::NUM_HASH_OUT_ELTS;

use crate::{generation::segments::SegmentError, GenerationSegmentData};

pub type Node = mpt_trie::partial_trie::Node<HashedPartialTrie>;
pub type BlockHeight = u64;

use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash,
    plonk::config::PoseidonGoldilocksConfig,
};

/// The base field on which statements are being proven.
pub type Field = GoldilocksField;
/// The recursive circuit configuration to be used to shrink and aggregate
/// proofs.
pub type RecursionConfig = PoseidonGoldilocksConfig;
/// The extension degree of the field used in the proof system.
pub const EXTENSION_DEGREE: usize = 2;

/// A type alias for EVM witness payloads.
pub type GenerationInputs = crate::generation::GenerationInputs<Field>;
/// A type alias for the trimmed version of EVM witness payloads.
pub type TrimmedGenerationInputs = crate::generation::TrimmedGenerationInputs<Field>;

pub type Hasher = PoseidonHash;
/// A type alias for plonky2 hash outputs.
pub type Hash = <Hasher as plonky2::plonk::config::Hasher<Field>>::Hash;

pub type ConsolidatedHash = [Field; NUM_HASH_OUT_ELTS];
pub use crate::proof::EMPTY_CONSOLIDATED_BLOCKHASH;

/// A type alias for recursive proofs generated by the zkEVM.
pub type ProofWithPublicInputs =
    plonky2::plonk::proof::ProofWithPublicInputs<Field, RecursionConfig, EXTENSION_DEGREE>;

/// A type alias for EVM public values used to generate and verify intermediate
/// proofs.
pub type PublicValues = crate::proof::PublicValues<Field>;

pub type AllData = Result<
    (TrimmedGenerationInputs, GenerationSegmentData),
    crate::generation::ErrorWithTries<SegmentError>,
>;

/// Returned type from the zkEVM STARK prover, before recursive verification.
pub type AllProof = crate::proof::AllProof<Field, RecursionConfig, EXTENSION_DEGREE>;

/// A type alias for the set of preprocessed circuits necessary to generate
/// succinct block proofs.
pub type AllRecursiveCircuits =
    crate::fixed_recursive_verifier::AllRecursiveCircuits<Field, RecursionConfig, EXTENSION_DEGREE>;

/// A type alias for the recursive chains of circuits needed to shrink EVM STARK
/// proofs.
pub type RecursiveCircuitsForTableSize =
    crate::fixed_recursive_verifier::RecursiveCircuitsForTableSize<
        Field,
        RecursionConfig,
        { EXTENSION_DEGREE },
    >;

/// A type alias for the verifier data necessary to verify succinct block
/// proofs.
/// While the prover state [`AllRecursiveCircuits`] can also verify proofs, this
/// [`VerifierData`] is much lighter, allowing anyone to verify block proofs,
/// regardless of the underlying hardware.
pub type VerifierData =
    plonky2::plonk::circuit_data::VerifierCircuitData<Field, RecursionConfig, EXTENSION_DEGREE>;
