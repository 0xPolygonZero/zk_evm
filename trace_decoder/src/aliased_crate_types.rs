//! This library links against two versions of the dependencies in `zk_evm`, and
//! this module handles the logic to work with both at once.
//!
//! Currently (this may change in the future), but SMT support is currently on
//! its own separate branch in `zk_evm`. We want to be able to support both
//! `MPT` (on the `main` branch) and SMT (on the `feat/type2` branch) in a
//! single binary. Because `feat/type2` modifies existing types that `main`
//! uses, we can not just simply use imports from both branches at the same
//! time. Instead, we need to make each version of the packages their own
//! separate dependency. This module just aliases the types to make them a bit
//! more readable, while also making it easier to merge the libraries together
//! later if the `feat/type2` eventually gets merged back into main.

macro_rules! create_aliased_type {
    ($alias_name:ident, $path:path) => {
        pub(crate) type $alias_name = $path;
    };
}

// MPT imports
create_aliased_type!(
    MptAccountRlp,
    evm_arithmetization_mpt::generation::mpt::AccountRlp
);
create_aliased_type!(MptBlockHashes, evm_arithmetization_mpt::proof::BlockHashes);
create_aliased_type!(
    MptBlockMetadata,
    evm_arithmetization_mpt::proof::BlockMetadata
);
create_aliased_type!(
    MptExtraBlockData,
    evm_arithmetization_mpt::proof::ExtraBlockData
);
create_aliased_type!(
    MptGenerationInputs,
    evm_arithmetization_mpt::generation::GenerationInputs
);
create_aliased_type!(
    MptTrieInputs,
    evm_arithmetization_mpt::generation::TrieInputs
);
create_aliased_type!(MptTrieRoots, evm_arithmetization_mpt::proof::TrieRoots);

// SMT imports
create_aliased_type!(
    SmtGenerationInputs,
    evm_arithmetization_smt::generation::GenerationInputs
);
