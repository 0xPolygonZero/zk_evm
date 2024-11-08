use evm_arithmetization::generation::mpt::{LegacyReceiptRlp, MptAccount};
use evm_arithmetization::generation::DebugOutputTries;
use mpt_trie::debug_tools::diff::{create_full_diff_between_tries, DiffPoint};
use mpt_trie::utils::TrieNodeType;
use tracing::info;

use crate::prover::BlockProverInput;

pub fn compare_tries(
    block_prover_input: &BlockProverInput,
    batch_index: usize,
    left: &DebugOutputTries,
    right: &DebugOutputTries,
) -> anyhow::Result<()> {
    let block_number = block_prover_input
        .other_data
        .b_data
        .b_meta
        .block_number
        .low_u64();

    fn compare_tries_and_output_results<
        K: rlp::Decodable + std::fmt::Debug,
        V: rlp::Decodable + std::fmt::Debug,
    >(
        trie_name: &str,
        diff_point: Vec<DiffPoint>,
        block_number: u64,
        batch_index: usize,
        decode_key: bool,
        decode_data: bool,
    ) -> anyhow::Result<()> {
        if diff_point.is_empty() {
            info!("{trie_name} for block {block_number} batch {batch_index} matches.");
            return Ok(());
        }
        for (index, trie_diff_point) in diff_point.into_iter().enumerate() {
            if trie_diff_point.a_info.node_type == TrieNodeType::Leaf {
                if let Some(ref td_value) = trie_diff_point.a_info.value {
                    let td_key_str: &str = if decode_key {
                        &format!(
                            "index: {:#?}",
                            rlp::decode::<K>(trie_diff_point.a_info.key.as_byte_slice())?
                        )
                    } else {
                        &format!("key: {}", trie_diff_point.a_info.key)
                    };
                    let td_data_str: &str = if decode_data {
                        &format!("{:#?}", rlp::decode::<V>(td_value)?)
                    } else {
                        &hex::encode(td_value)
                    };
                    info!("Trace decoder {trie_name} block {block_number} batch {batch_index} {td_key_str} data: {td_data_str}");
                } else {
                    info!("Trace decoder {trie_name} block {block_number} batch {batch_index}, skip data printout as diff is not at the leaf node level.");
                }
            }
            if trie_diff_point.b_info.node_type == TrieNodeType::Leaf {
                if let Some(ref prover_value) = trie_diff_point.b_info.value {
                    let prover_key_str: &str = if decode_key {
                        &format!(
                            "index: {:#?}",
                            rlp::decode::<K>(trie_diff_point.b_info.key.as_byte_slice())?
                        )
                    } else {
                        &format!("key: {}", trie_diff_point.b_info.key)
                    };
                    let prover_data_str: &str = if decode_data {
                        &format!("{:#?}", rlp::decode::<V>(prover_value)?)
                    } else {
                        &hex::encode(prover_value)
                    };
                    info!("Prover {trie_name} block {block_number} batch {batch_index} {prover_key_str} data: {prover_data_str}");
                } else {
                    info!("Prover {trie_name} block {block_number} batch {batch_index}, skip data printout as diff is not at the leaf node level.");
                }
            }

            info!(
                "Diff {index} {trie_name} block {block_number} batch {batch_index} diff:\n{}\n",
                trie_diff_point
            );
        }
        Ok(())
    }

    let state_trie_diff = create_full_diff_between_tries(&left.state_trie, &right.state_trie);
    compare_tries_and_output_results::<usize, MptAccount>(
        "state trie",
        state_trie_diff.diff_points,
        block_number,
        batch_index,
        false,
        true,
    )?;

    let transaction_trie_diff =
        create_full_diff_between_tries(&left.transaction_trie, &right.transaction_trie);
    compare_tries_and_output_results::<usize, u8>(
        "transaction trie",
        transaction_trie_diff.diff_points,
        block_number,
        batch_index,
        false,
        true,
    )?;

    let receipt_trie_diff = create_full_diff_between_tries(&left.receipt_trie, &right.receipt_trie);
    compare_tries_and_output_results::<usize, LegacyReceiptRlp>(
        "receipt trie",
        receipt_trie_diff.diff_points,
        block_number,
        batch_index,
        true,
        true,
    )?;

    Ok(())
}
