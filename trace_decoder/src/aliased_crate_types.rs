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

use crate::compact;

macro_rules! include_feature_gated_evm_deps {
    ($crate_name:ident) => {
        pub(crate) use $crate_name::generation::mpt::AccountRlp;
        pub(crate) use $crate_name::generation::mpt::LegacyReceiptRlp;
        pub(crate) use $crate_name::generation::GenerationInputs;
        pub(crate) use $crate_name::generation::TrieInputs;
        pub(crate) use $crate_name::proof::BlockHashes;
        pub(crate) use $crate_name::proof::BlockMetadata;
        pub(crate) use $crate_name::proof::ExtraBlockData;
        pub(crate) use $crate_name::proof::TrieRoots;
        pub(crate) use $crate_name::GenerationInputs as ProofGenIR;
    };
}

macro_rules! include_feature_gated_mpt_trie_deps {
    ($crate_name:ident) => {
        pub(crate) use $crate_name::nibbles::FromHexPrefixError;
        pub(crate) use $crate_name::nibbles::Nibbles;
        pub(crate) use $crate_name::partial_trie::HashedPartialTrie;
        pub(crate) use $crate_name::partial_trie::PartialTrie;
        pub(crate) use $crate_name::trie_ops::TrieOpError;
        pub(crate) use $crate_name::trie_ops::ValOrHash;
        pub(crate) use $crate_name::trie_subsets;
        pub(crate) use $crate_name::trie_subsets::SubsetTrieError;
    };
}

cfg_if! {
    if #[cfg(feature = "mpt")] {
        include_feature_gated_evm_deps!(evm_arithmetization_mpt);
        include_feature_gated_mpt_trie_deps!(mpt_trie_normal);

        pub(crate) use compact::compact_mpt_processing::MptPreImageProcessing as PreImageProcessing;
    }
    else if #[cfg(feature = "smt")] {
        include_feature_gated_evm_deps!(evm_arithmetization_smt);
        include_feature_gated_mpt_trie_deps!(mpt_trie_type2);

        pub(crate) use compact::compact_smt_processing::SmtPreImageProcessing as PreImageProcessing;
    }
}
