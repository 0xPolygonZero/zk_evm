use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::DebugOutputTries;
use mpt_trie::debug_tools::diff::create_diff_between_tries;
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
    let state_trie_diff = create_diff_between_tries(&left.state_trie, &right.state_trie);
    if let Some(ref state_trie_diff_point) = state_trie_diff.latest_diff_res {
        if state_trie_diff_point.a_info.node_type == TrieNodeType::Leaf {
            if let Some(ref td_account_value) = state_trie_diff_point.a_info.value {
                let td_account_data = rlp::decode::<AccountRlp>(td_account_value)?;
                info!("Trace decoder state trie block {block_number} batch {batch_index} account address hash: {} account data: {:#?}",
                    state_trie_diff_point.a_info.key, td_account_data);
            } else {
                info!("Trace decoder state trie block {block_number} batch {batch_index}, skip account printout as diff is not at the leaf node level.");
            }
        }
        if state_trie_diff_point.b_info.node_type == TrieNodeType::Leaf {
            if let Some(ref prover_account_value) = state_trie_diff_point.b_info.value {
                let prover_account_data = rlp::decode::<AccountRlp>(prover_account_value)?;
                info!("Prover state trie block {block_number} batch {batch_index} account address hash: {} account data: {:#?}",
                    state_trie_diff_point.b_info.key, prover_account_data);
            } else {
                info!("Prover state trie block {block_number} batch {batch_index}, skip account printout as diff is not at the leaf node level.");
            }
        }

        info!(
            "State trie block {block_number} batch {batch_index} diff: {:#?}",
            state_trie_diff_point
        );
    } else {
        info!("State trie for block {block_number} batch {batch_index} matches.");
    }

    let transaction_trie_diff =
        create_diff_between_tries(&left.transaction_trie, &right.transaction_trie);
    if let Some(ref transaction_trie_diff_point) = transaction_trie_diff.latest_diff_res {
        if transaction_trie_diff_point.a_info.node_type == TrieNodeType::Leaf {
            let tx_index =
                rlp::decode::<usize>(transaction_trie_diff_point.a_info.key.as_byte_slice())?;
            info!("Trace decoder transaction trie block {block_number} batch {batch_index} transaction index {tx_index} rlp bytecode: {:?}",
                    transaction_trie_diff_point.a_info.value.as_ref().map(hex::encode));
        } else {
            info!("Trace decoder transaction trie block {block_number} batch {batch_index}, skip tx printout as diff is not at the leaf node level.");
        }
        if transaction_trie_diff_point.b_info.node_type == TrieNodeType::Leaf {
            let tx_index =
                rlp::decode::<usize>(transaction_trie_diff_point.b_info.key.as_byte_slice())?;
            info!("Prover transaction trie block {block_number} batch {batch_index} transaction index {tx_index} rlp bytecode: {:?}",
                        transaction_trie_diff_point.b_info.value.as_ref().map(hex::encode));
        } else {
            info!("Prover transaction trie block {block_number} batch {batch_index}, skip tx printout as diff is not at the leaf node level.");
        }

        info!(
            "Transactions trie block {block_number} batch {batch_index} diff: {:#?}",
            transaction_trie_diff_point
        );
    } else {
        info!("Transaction trie for block {block_number} batch {batch_index} matches.");
    }

    let receipt_trie_diff = create_diff_between_tries(&left.receipt_trie, &right.receipt_trie);
    if let Some(ref receipt_trie_diff_point) = receipt_trie_diff.latest_diff_res {
        if receipt_trie_diff_point.a_info.node_type == TrieNodeType::Leaf {
            if let Some(ref td_receipt_value) = receipt_trie_diff_point.a_info.value {
                let tx_index =
                    rlp::decode::<usize>(receipt_trie_diff_point.a_info.key.as_byte_slice())?;
                let td_receipt_data = rlp::decode::<LegacyReceiptRlp>(td_receipt_value)?;
                info!("Trace decoder receipt trie block {block_number} batch {batch_index} output tx index: {tx_index} receipt data: {:#?}", td_receipt_data);
            } else {
                info!("Trace decoder receipt trie block {block_number} batch {batch_index}, skip printout as diff is not at the leaf node level.");
            }
        }

        if receipt_trie_diff_point.b_info.node_type == TrieNodeType::Leaf {
            if let Some(ref prover_receipt_value) = receipt_trie_diff_point.b_info.value {
                let tx_index =
                    rlp::decode::<usize>(receipt_trie_diff_point.b_info.key.as_byte_slice())?;
                let prover_receipt_data = rlp::decode::<LegacyReceiptRlp>(prover_receipt_value)?;
                info!("Prover receipt trie block {block_number} batch {batch_index} output tx index: {tx_index} receipt data: {:#?}", prover_receipt_data);
            } else {
                info!("Prover receipt trie block {block_number} batch {batch_index}, skip receipt printout as diff is not at the leaf node level.");
            }
        }

        println!(
            "Receipt trie block {block_number} batch {batch_index} diff: {:#?}",
            receipt_trie_diff
        );
    } else {
        println!("Receipt trie block {block_number} batch {batch_index} matches.");
    }

    Ok(())
}
