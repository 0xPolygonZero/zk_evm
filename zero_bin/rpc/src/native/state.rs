use std::collections::{HashMap, HashSet};

use alloy::{
    primitives::{keccak256, Address, StorageKey, B256},
    providers::Provider,
    rpc::types::eth::{Block, BlockTransactionsKind, EIP1186AccountProofResponse},
    transports::Transport,
};
use anyhow::Context as _;
use futures::future::{try_join, try_join_all};
use mpt_trie::{builder::PartialTrieBuilder, partial_trie::HashedPartialTrie};
use trace_decoder::trace_protocol::{
    BlockTraceTriePreImages, SeparateStorageTriesPreImage, SeparateTriePreImage,
    SeparateTriePreImages, TrieDirect, TxnInfo,
};

use crate::compat::Compat;

/// Processes the state witness for the given block.
pub async fn process_state_witness<ProviderT, TransportT>(
    provider: &ProviderT,
    block: Block,
    txn_infos: &[TxnInfo],
) -> anyhow::Result<BlockTraceTriePreImages>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let state_access = process_states_access(txn_infos, &block)?;

    let block_number = block
        .header
        .number
        .context("Block number not returned with block")?;
    let prev_state_root = provider
        .get_block((block_number - 1).into(), BlockTransactionsKind::Hashes)
        .await?
        .context("Failed to get previous block")?
        .header
        .state_root;

    let (state, storage_proofs) =
        generate_state_witness(prev_state_root, state_access, provider, block_number).await?;

    Ok(BlockTraceTriePreImages::Separate(SeparateTriePreImages {
        state: SeparateTriePreImage::Direct(TrieDirect(state.build())),
        storage: SeparateStorageTriesPreImage::MultipleTries(
            storage_proofs
                .into_iter()
                .map(|(a, m)| {
                    (
                        a.compat(),
                        SeparateTriePreImage::Direct(TrieDirect(m.build())),
                    )
                })
                .collect(),
        ),
    }))
}

/// Iterate over the tx_infos and process the state access for each address.
/// Also includes the state access for withdrawals and the block author.
///
/// Returns a map from address to the set of storage keys accessed by that
/// address.
pub fn process_states_access(
    tx_infos: &[TxnInfo],
    block: &Block,
) -> anyhow::Result<HashMap<Address, HashSet<StorageKey>>> {
    let mut state_access = HashMap::<Address, HashSet<StorageKey>>::new();

    if let Some(w) = block.withdrawals.as_ref() {
        w.iter().for_each(|w| {
            state_access.insert(w.address, Default::default());
        })
    };
    state_access.insert(block.header.miner, Default::default());

    for txn_info in tx_infos {
        for (address, trace) in txn_info.traces.iter() {
            let address_storage_access = state_access.entry((*address).compat()).or_default();

            if let Some(read_keys) = trace.storage_read.as_ref() {
                address_storage_access.extend(read_keys.iter().copied().map(Compat::compat));
            }

            if let Some(written_keys) = trace.storage_written.as_ref() {
                address_storage_access.extend(written_keys.keys().copied().map(Compat::compat));
            }
        }
    }

    Ok(state_access)
}

/// Generates the state witness for the given block.
async fn generate_state_witness<ProviderT, TransportT>(
    prev_state_root: B256,
    accounts_state: HashMap<Address, HashSet<StorageKey>>,
    provider: &ProviderT,
    block_number: u64,
) -> anyhow::Result<(
    PartialTrieBuilder<HashedPartialTrie>,
    HashMap<B256, PartialTrieBuilder<HashedPartialTrie>>,
)>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let mut state = PartialTrieBuilder::new(prev_state_root.compat(), Default::default());
    let mut storage_proofs = HashMap::<B256, PartialTrieBuilder<HashedPartialTrie>>::new();

    let (account_proofs, next_account_proofs) =
        fetch_proof_data(accounts_state, provider, block_number).await?;

    // Insert account proofs
    for (address, proof) in account_proofs.into_iter() {
        state.insert_proof(proof.account_proof.compat());

        let storage_mpt =
            storage_proofs
                .entry(keccak256(address))
                .or_insert(PartialTrieBuilder::new(
                    proof.storage_hash.compat(),
                    Default::default(),
                ));
        for proof in proof.storage_proof {
            storage_mpt.insert_proof(proof.proof.compat());
        }
    }

    // Insert short node variants from next proofs
    for (address, proof) in next_account_proofs.into_iter() {
        state.insert_short_node_variants_from_proof(proof.account_proof.compat());

        if let Some(storage_mpt) = storage_proofs.get_mut(&keccak256(address)) {
            for proof in proof.storage_proof {
                storage_mpt.insert_short_node_variants_from_proof(proof.proof.compat());
            }
        }
    }

    Ok((state, storage_proofs))
}

/// Fetches the proof data for the given accounts and associated storage keys.
async fn fetch_proof_data<ProviderT, TransportT>(
    accounts_state: HashMap<Address, HashSet<StorageKey>>,
    provider: &ProviderT,
    block_number: u64,
) -> anyhow::Result<(
    Vec<(Address, EIP1186AccountProofResponse)>,
    Vec<(Address, EIP1186AccountProofResponse)>,
)>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let account_proofs_fut = accounts_state
        .clone()
        .into_iter()
        .map(|(address, keys)| async move {
            let proof = provider
                .get_proof(address, keys.into_iter().collect())
                .block_id((block_number - 1).into())
                .await
                .context("Failed to get proof for account")?;
            anyhow::Result::Ok((address, proof))
        })
        .collect::<Vec<_>>();

    let next_account_proofs_fut = accounts_state
        .into_iter()
        .map(|(address, keys)| async move {
            let proof = provider
                .get_proof(address, keys.into_iter().collect())
                .block_id(block_number.into())
                .await
                .context("Failed to get proof for account")?;
            anyhow::Result::Ok((address, proof))
        });

    try_join(
        try_join_all(account_proofs_fut),
        try_join_all(next_account_proofs_fut),
    )
    .await
}
