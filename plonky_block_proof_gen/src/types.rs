use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};

pub type PlonkyProofIntern = ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>;

pub type AllRecursiveCircuits = plonky2_evm::fixed_recursive_verifier::AllRecursiveCircuits<
    GoldilocksField,
    PoseidonGoldilocksConfig,
    2,
>;
