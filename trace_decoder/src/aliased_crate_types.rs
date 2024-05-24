//! This library links against two versions of the dependencies in `zk_evm`, and
//! this module handles the logic to work with both at once.
//!
//! Currently (this may change in the future), but SMT support is currently on
//! its own separate branch in `zk_evm`. We want to be able to support both
//! `MPT` (on the `main` branch) and SMT (on the `feat/type2` branch) using
//! feature gating. Because `feat/type2` modifies existing types that `main`
//! uses, we can not just simply use imports from both branches at the same
//! time. Instead, we need to make each version of the packages their own
//! separate dependency. This module just aliases the types to make them a bit
//! more readable, while also making it easier to merge the libraries together
//! later if the `feat/type2` eventually gets merged back into main.

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
    }
    else if #[cfg(feature = "smt")] {
        include_feature_gated_zero_deps!(evm_arithmetization_smt);
    }
}
