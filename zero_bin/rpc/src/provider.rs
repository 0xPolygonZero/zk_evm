use std::sync::Arc;

use alloy::primitives::BlockHash;
use alloy::rpc::types::{Block, BlockId, BlockTransactionsKind};
use alloy::{providers::Provider, transports::Transport};
use anyhow::Context;
use tokio::sync::Mutex;

const CACHE_SIZE: usize = 1024;

/// Wrapper around alloy provider to cache blocks and other
/// frequently used data.
pub struct CachedProvider<ProviderT, TransportT> {
    provider: ProviderT,
    blocks_by_number: Arc<Mutex<lru::LruCache<u64, Block>>>,
    blocks_by_hash: Arc<Mutex<lru::LruCache<BlockHash, u64>>>,
    _phantom: std::marker::PhantomData<TransportT>,
}

impl<ProviderT, TransportT> CachedProvider<ProviderT, TransportT>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    pub fn new(provider: ProviderT) -> Self {
        Self {
            provider,
            blocks_by_number: Arc::new(Mutex::new(lru::LruCache::new(
                std::num::NonZero::new(CACHE_SIZE).unwrap(),
            ))),
            blocks_by_hash: Arc::new(Mutex::new(lru::LruCache::new(
                std::num::NonZero::new(CACHE_SIZE).unwrap(),
            ))),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn as_mut_provider(&mut self) -> &mut ProviderT {
        &mut self.provider
    }

    pub const fn as_provider(&self) -> &ProviderT {
        &self.provider
    }

    /// Retrieves block by number or hash, caching it if it's not already
    /// cached.
    pub async fn get_block(
        &self,
        id: BlockId,
        kind: BlockTransactionsKind,
    ) -> anyhow::Result<Block> {
        let cached_block = match id {
            BlockId::Hash(hash) => {
                let block_num = self
                    .blocks_by_hash
                    .lock()
                    .await
                    .get(&hash.block_hash)
                    .copied();
                if let Some(block_num) = block_num {
                    self.blocks_by_number.lock().await.get(&block_num).cloned()
                } else {
                    None
                }
            }
            BlockId::Number(alloy::rpc::types::BlockNumberOrTag::Number(number)) => {
                self.blocks_by_number.lock().await.get(&number).cloned()
            }
            _ => None,
        };

        if let Some(block) = cached_block {
            Ok(block)
        } else {
            let block = self
                .provider
                .get_block(id, kind)
                .await?
                .context(format!("target block {:?} does not exist", id))?;

            if let Some(block_num) = block.header.number {
                self.blocks_by_number
                    .lock()
                    .await
                    .put(block_num, block.clone());
                if let Some(hash) = block.header.hash {
                    self.blocks_by_hash.lock().await.put(hash, block_num);
                }
            }
            Ok(block)
        }
    }
}
