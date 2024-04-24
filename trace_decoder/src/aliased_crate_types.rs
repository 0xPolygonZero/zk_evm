use cfg_if::cfg_if;

macro_rules! include_feature_gated_zero_deps {
    ($crate_name:ident) => {
        pub(crate) type AccountRlp = $crate_name::generation::mpt::AccountRlp;
        pub(crate) type BlockHashes = $crate_name::proof::BlockHashes;
        pub(crate) type BlockMetadata = $crate_name::proof::BlockMetadata;
        pub(crate) type ExtraBlockData = $crate_name::proof::ExtraBlockData;
        pub(crate) type GenerationInputs = $crate_name::generation::GenerationInputs;
        pub(crate) type LegacyReceiptRlp = $crate_name::generation::mpt::LegacyReceiptRlp;
        pub(crate) type ProofGenIR = $crate_name::GenerationInputs;
        pub(crate) type TrieInputs = $crate_name::generation::TrieInputs;
        pub(crate) type TrieRoots = $crate_name::proof::TrieRoots;
    };
}

cfg_if! {
    if #[cfg(feature = "mpt")] {
        include_feature_gated_zero_deps!(evm_arithmetization_mpt);
    } else if #[cfg(feature = "smt")] {
        include_feature_gated_zero_deps!(evm_arithmetization_smt);
    }

}
