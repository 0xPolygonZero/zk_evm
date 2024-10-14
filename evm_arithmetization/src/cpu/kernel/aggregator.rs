//! Loads each kernel assembly file and concatenates them.

use std::collections::HashSet;

use itertools::Itertools;
use once_cell::sync::Lazy;

use super::assembler::{assemble, Kernel};
use crate::cpu::kernel::constants::evm_constants;
use crate::cpu::kernel::parser::parse;

pub const NUMBER_KERNEL_FILES: usize = if cfg!(feature = "eth_mainnet") {
    158
} else if cfg!(feature = "cdk_erigon") || cfg!(feature = "polygon_pos") {
    159
} else {
    // unreachable
    0
};

pub static KERNEL_FILES: [&str; NUMBER_KERNEL_FILES] = [
    "global jumped_to_0: PANIC",
    "global jumped_to_1: PANIC",
    include_str!("asm/beacon_roots.asm"),
    include_str!("asm/bignum/add.asm"),
    include_str!("asm/bignum/addmul.asm"),
    include_str!("asm/bignum/cmp.asm"),
    include_str!("asm/bignum/isone.asm"),
    include_str!("asm/bignum/iszero.asm"),
    include_str!("asm/bignum/modexp.asm"),
    include_str!("asm/bignum/modmul.asm"),
    include_str!("asm/bignum/mul.asm"),
    include_str!("asm/bignum/shr.asm"),
    include_str!("asm/bignum/util.asm"),
    include_str!("asm/core/call.asm"),
    include_str!("asm/core/call_gas.asm"),
    include_str!("asm/core/create.asm"),
    include_str!("asm/core/create_addresses.asm"),
    #[cfg(feature = "eth_mainnet")]
    include_str!("asm/core/create_contract_account.asm"),
    #[cfg(feature = "cdk_erigon")]
    include_str!("asm/core/create_type2_contract_account.asm"),
    include_str!("asm/core/exception.asm"),
    include_str!("asm/core/create_receipt.asm"),
    include_str!("asm/core/gas.asm"),
    include_str!("asm/core/intrinsic_gas.asm"),
    #[cfg(feature = "eth_mainnet")]
    include_str!("asm/core/jumpdest_analysis.asm"),
    include_str!("asm/core/nonce.asm"),
    include_str!("asm/core/process_txn.asm"),
    include_str!("asm/core/syscall.asm"),
    include_str!("asm/core/terminate.asm"),
    #[cfg(feature = "eth_mainnet")]
    include_str!("asm/core/transfer.asm"),
    #[cfg(feature = "cdk_erigon")]
    include_str!("asm/core/transfer_cdk_erigon.asm"),
    include_str!("asm/core/util.asm"),
    include_str!("asm/core/access_lists.asm"),
    include_str!("asm/core/log.asm"),
    include_str!("asm/core/selfdestruct_list.asm"),
    include_str!("asm/core/touched_addresses.asm"),
    #[cfg(feature = "eth_mainnet")]
    include_str!("asm/core/withdrawals.asm"),
    include_str!("asm/core/precompiles/main.asm"),
    include_str!("asm/core/precompiles/ecrec.asm"),
    include_str!("asm/core/precompiles/sha256.asm"),
    include_str!("asm/core/precompiles/rip160.asm"),
    include_str!("asm/core/precompiles/id.asm"),
    include_str!("asm/core/precompiles/expmod.asm"),
    include_str!("asm/core/precompiles/bn_add.asm"),
    include_str!("asm/core/precompiles/bn_mul.asm"),
    include_str!("asm/core/precompiles/snarkv.asm"),
    include_str!("asm/core/precompiles/blake2_f.asm"),
    #[cfg(feature = "eth_mainnet")]
    include_str!("asm/core/precompiles/kzg_peval.asm"),
    // include_str!("asm/curve/bls381/util.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/constants.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/curve_add.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/curve_mul.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/final_exponent.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/glv.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/miller_loop.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/msm.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/pairing.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/precomputation.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/twisted_curve_add.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/twisted_curve_checks.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/twisted_curve_endomorphism.asm"),
    include_str!("asm/curve/bn254/curve_arithmetic/twisted_curve_mul.asm"),
    include_str!("asm/curve/bn254/field_arithmetic/degree_6_mul.asm"),
    include_str!("asm/curve/bn254/field_arithmetic/degree_12_mul.asm"),
    include_str!("asm/curve/bn254/field_arithmetic/frobenius.asm"),
    include_str!("asm/curve/bn254/field_arithmetic/inverse.asm"),
    include_str!("asm/curve/bn254/field_arithmetic/util.asm"),
    include_str!("asm/curve/common.asm"),
    include_str!("asm/curve/secp256k1/curve_add.asm"),
    include_str!("asm/curve/secp256k1/ecrecover.asm"),
    include_str!("asm/curve/secp256k1/inverse_scalar.asm"),
    include_str!("asm/curve/secp256k1/lift_x.asm"),
    include_str!("asm/curve/secp256k1/moddiv.asm"),
    include_str!("asm/curve/secp256k1/glv.asm"),
    include_str!("asm/curve/secp256k1/precomputation.asm"),
    include_str!("asm/curve/wnaf.asm"),
    include_str!("asm/exp.asm"),
    include_str!("asm/halt.asm"),
    include_str!("asm/hash/blake2/addresses.asm"),
    include_str!("asm/hash/blake2/blake2_f.asm"),
    // include_str!("asm/hash/blake2/blake2b.asm"),
    // include_str!("asm/hash/blake2/compression.asm"),
    include_str!("asm/hash/blake2/g_functions.asm"),
    include_str!("asm/hash/blake2/hash.asm"),
    include_str!("asm/hash/blake2/iv.asm"),
    include_str!("asm/hash/blake2/ops.asm"),
    include_str!("asm/hash/blake2/permutations.asm"),
    include_str!("asm/hash/ripemd/box.asm"),
    include_str!("asm/hash/ripemd/compression.asm"),
    include_str!("asm/hash/ripemd/constants.asm"),
    include_str!("asm/hash/ripemd/functions.asm"),
    include_str!("asm/hash/ripemd/main.asm"),
    include_str!("asm/hash/ripemd/update.asm"),
    include_str!("asm/hash/sha2/compression.asm"),
    include_str!("asm/hash/sha2/constants.asm"),
    include_str!("asm/hash/sha2/main.asm"),
    include_str!("asm/hash/sha2/message_schedule.asm"),
    include_str!("asm/hash/sha2/ops.asm"),
    include_str!("asm/hash/sha2/temp_words.asm"),
    include_str!("asm/hash/sha2/write_length.asm"),
    include_str!("asm/main.asm"),
    #[cfg(feature = "eth_mainnet")]
    include_str!("asm/linked_list/accounts_linked_list.asm"),
    #[cfg(feature = "eth_mainnet")]
    include_str!("asm/linked_list/storage_linked_list.asm"),
    #[cfg(feature = "eth_mainnet")]
    include_str!("asm/linked_list/final_tries.asm"),
    #[cfg(feature = "eth_mainnet")]
    include_str!("asm/linked_list/initial_tries.asm"),
    #[cfg(feature = "cdk_erigon")]
    include_str!("asm/linked_list/type2/state_linked_list.asm"),
    #[cfg(feature = "cdk_erigon")]
    include_str!("asm/linked_list/type2/final_tries.asm"),
    #[cfg(feature = "cdk_erigon")]
    include_str!("asm/linked_list/type2/initial_tries.asm"),
    include_str!("asm/memory/core.asm"),
    include_str!("asm/memory/memcpy.asm"),
    include_str!("asm/memory/memset.asm"),
    include_str!("asm/memory/metadata.asm"),
    include_str!("asm/memory/packing.asm"),
    include_str!("asm/memory/syscalls.asm"),
    include_str!("asm/memory/txn_fields.asm"),
    include_str!("asm/memory/transient_storage.asm"),
    include_str!("asm/mpt/accounts.asm"),
    include_str!("asm/mpt/delete/delete.asm"),
    include_str!("asm/mpt/delete/delete_branch.asm"),
    include_str!("asm/mpt/delete/delete_extension.asm"),
    include_str!("asm/mpt/hash/hash.asm"),
    include_str!("asm/mpt/hash/hash_trie_specific.asm"),
    include_str!("asm/mpt/hex_prefix.asm"),
    include_str!("asm/mpt/insert/insert.asm"),
    include_str!("asm/mpt/insert/insert_extension.asm"),
    include_str!("asm/mpt/insert/insert_leaf.asm"),
    include_str!("asm/mpt/insert/insert_trie_specific.asm"),
    include_str!("asm/mpt/read.asm"),
    include_str!("asm/mpt/storage/storage_read.asm"),
    include_str!("asm/mpt/storage/storage_write.asm"),
    include_str!("asm/mpt/util.asm"),
    include_str!("asm/rlp/decode.asm"),
    include_str!("asm/rlp/encode.asm"),
    include_str!("asm/rlp/encode_rlp_scalar.asm"),
    include_str!("asm/rlp/encode_rlp_string.asm"),
    include_str!("asm/rlp/increment_bounded_rlp.asm"),
    include_str!("asm/rlp/num_bytes.asm"),
    include_str!("asm/rlp/read_to_memory.asm"),
    include_str!("asm/shift.asm"),
    include_str!("asm/signed.asm"),
    #[cfg(feature = "cdk_erigon")]
    include_str!("asm/smt/hash.asm"),
    #[cfg(feature = "cdk_erigon")]
    include_str!("asm/smt/keys.asm"),
    #[cfg(feature = "cdk_erigon")]
    include_str!("asm/smt/utils.asm"),
    #[cfg(feature = "cdk_erigon")]
    include_str!("asm/smt/delete.asm"),
    #[cfg(feature = "cdk_erigon")]
    include_str!("asm/smt/read.asm"),
    include_str!("asm/journal/journal.asm"),
    include_str!("asm/journal/account_loaded.asm"),
    include_str!("asm/journal/account_destroyed.asm"),
    include_str!("asm/journal/account_touched.asm"),
    include_str!("asm/journal/balance_transfer.asm"),
    include_str!("asm/journal/nonce_change.asm"),
    include_str!("asm/journal/storage_change.asm"),
    include_str!("asm/journal/storage_loaded.asm"),
    include_str!("asm/journal/code_change.asm"),
    include_str!("asm/journal/refund.asm"),
    include_str!("asm/journal/account_created.asm"),
    include_str!("asm/journal/revert.asm"),
    include_str!("asm/journal/log.asm"),
    include_str!("asm/journal/transient_storage_change.asm"),
    include_str!("asm/transactions/common_decoding.asm"),
    include_str!("asm/transactions/router.asm"),
    include_str!("asm/transactions/type_0.asm"),
    include_str!("asm/transactions/type_1.asm"),
    include_str!("asm/transactions/type_2.asm"),
    #[cfg(feature = "eth_mainnet")]
    include_str!("asm/transactions/type_3.asm"),
    include_str!("asm/util/assertions.asm"),
    include_str!("asm/util/basic_macros.asm"),
    include_str!("asm/util/keccak.asm"),
    include_str!("asm/util/math.asm"),
    include_str!("asm/account_code.asm"),
    include_str!("asm/balance.asm"),
    include_str!("asm/bloom_filter.asm"),
    #[cfg(feature = "cdk_erigon")]
    include_str!("asm/cdk_pre_execution.asm"),
];

pub static KERNEL: Lazy<Kernel> = Lazy::new(combined_kernel);

pub(crate) fn combined_kernel_from_files<const N: usize>(files: [&str; N]) -> Kernel {
    let mut active_features = HashSet::new();
    if cfg!(feature = "cdk_erigon") {
        active_features.insert("cdk_erigon");
    } else if cfg!(feature = "polygon_pos") {
        active_features.insert("polygon_pos");
    } else {
        active_features.insert("eth_mainnet");
    }

    let parsed_files = files
        .iter()
        .map(|f| parse(f, &active_features))
        .collect_vec();
    assemble(parsed_files, evm_constants(), true)
}

pub(crate) fn combined_kernel() -> Kernel {
    combined_kernel_from_files(KERNEL_FILES)
}

#[cfg(test)]
mod tests {
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    use log::debug;

    use crate::cpu::kernel::aggregator::combined_kernel;

    #[test]
    fn make_kernel() {
        let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));

        // Make sure we can parse and assemble the entire kernel.
        let kernel = combined_kernel();
        debug!("Total kernel size: {} bytes", kernel.code.len());
    }
}
