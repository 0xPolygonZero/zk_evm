use plonky2::{field::extension::Extendable, hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use crate::proof::{BlockHashesTarget, BlockMetadataTarget, ExtraBlockDataTarget, PublicValuesTarget, TrieRootsTarget};

/// This file contains copies of the same functions in [`recursive_verifier.rs`], but without the registering the targets.
/// This is useful when we want to supply public values privately into a circuit.

pub(crate) fn add_virtual_public_values<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> PublicValuesTarget {
    let trie_roots_before = add_virtual_trie_roots(builder);
    let trie_roots_after = add_virtual_trie_roots(builder);
    let block_metadata = add_virtual_block_metadata(builder);
    let block_hashes = add_virtual_block_hashes(builder);
    let extra_block_data = add_virtual_extra_block_data(builder);
    PublicValuesTarget {
        trie_roots_before,
        trie_roots_after,
        block_metadata,
        block_hashes,
        extra_block_data,
    }
}

pub(crate) fn add_virtual_trie_roots<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> TrieRootsTarget {
    let state_root = builder.add_virtual_target_arr();
    let transactions_root = builder.add_virtual_target_arr();
    let receipts_root = builder.add_virtual_target_arr();
    TrieRootsTarget {
        state_root,
        transactions_root,
        receipts_root,
    }
}

pub(crate) fn add_virtual_block_metadata<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> BlockMetadataTarget {
    let block_beneficiary = builder.add_virtual_target_arr();
    let block_timestamp = builder.add_virtual_target();
    let block_number = builder.add_virtual_target();
    let block_difficulty = builder.add_virtual_target();
    let block_random = builder.add_virtual_target_arr();
    let block_gaslimit = builder.add_virtual_target();
    let block_chain_id = builder.add_virtual_target();
    let block_base_fee = builder.add_virtual_target_arr();
    let block_gas_used = builder.add_virtual_target();
    let block_bloom = builder.add_virtual_target_arr();
    BlockMetadataTarget {
        block_beneficiary,
        block_timestamp,
        block_number,
        block_difficulty,
        block_random,
        block_gaslimit,
        block_chain_id,
        block_base_fee,
        block_gas_used,
        block_bloom,
    }
}

pub(crate) fn add_virtual_block_hashes<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> BlockHashesTarget {
    let prev_hashes = builder.add_virtual_target_arr();
    let cur_hash = builder.add_virtual_target_arr();
    BlockHashesTarget {
        prev_hashes,
        cur_hash,
    }
}
pub(crate) fn add_virtual_extra_block_data<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ExtraBlockDataTarget {
    let checkpoint_state_trie_root = builder.add_virtual_target_arr();
    let txn_number_before = builder.add_virtual_target();
    let txn_number_after = builder.add_virtual_target();
    let gas_used_before = builder.add_virtual_target();
    let gas_used_after = builder.add_virtual_target();
    ExtraBlockDataTarget {
        checkpoint_state_trie_root,
        txn_number_before,
        txn_number_after,
        gas_used_before,
        gas_used_after,
    }
}