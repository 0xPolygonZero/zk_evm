use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use alloy::primitives::BlockHash;
use alloy::rpc::types::{Block, BlockId, BlockTransactionsKind};
use alloy::{providers::Provider, transports::Transport};
use anyhow::Context;
use mockall::automock;
use tokio::sync::{Mutex, Semaphore, SemaphorePermit};

use crate::rpc::RpcType;

const CACHE_SIZE: usize = 1024;
const MAX_NUMBER_OF_PARALLEL_REQUESTS: usize = 128;

#[automock]
pub trait BlockProvider {
    fn get_block_by_id(
        &self,
        block_id: BlockId,
    ) -> impl Future<Output = anyhow::Result<Option<Block>>> + Send;

    fn latest_block_number(&self) -> impl Future<Output = anyhow::Result<u64>> + Send;
}

/// Wrapper around alloy provider to cache blocks and other
/// frequently used data.
pub struct CachedProvider<ProviderT, TransportT> {
    provider: Arc<ProviderT>,
    // `Alloy` provider is using `Reqwest` http client under the hood. It has an unbounded
    // connection pool. We need to limit the number of parallel connections by ourselves, so we
    // use semaphore to count the number of parallel RPC requests happening at any moment with
    // CachedProvider.
    semaphore: Arc<Semaphore>,
    blocks_by_number: Arc<Mutex<lru::LruCache<u64, Block>>>,
    blocks_by_hash: Arc<Mutex<lru::LruCache<BlockHash, u64>>>,
    _phantom: std::marker::PhantomData<TransportT>,

    pub rpc_type: RpcType,
}

pub struct ProviderGuard<'a, ProviderT> {
    provider: Arc<ProviderT>,
    _permit: SemaphorePermit<'a>,
}

impl<'a, ProviderT> Deref for ProviderGuard<'a, ProviderT> {
    type Target = Arc<ProviderT>;

    fn deref(&self) -> &Self::Target {
        &self.provider
    }
}

impl<ProviderT> DerefMut for ProviderGuard<'_, ProviderT> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.provider
    }
}

impl<ProviderT, TransportT> CachedProvider<ProviderT, TransportT>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    pub fn new(provider: ProviderT, rpc_type: RpcType) -> Self {
        Self {
            provider: provider.into(),
            semaphore: Arc::new(Semaphore::new(MAX_NUMBER_OF_PARALLEL_REQUESTS)),
            blocks_by_number: Arc::new(Mutex::new(lru::LruCache::new(
                std::num::NonZero::new(CACHE_SIZE).unwrap(),
            ))),
            blocks_by_hash: Arc::new(Mutex::new(lru::LruCache::new(
                std::num::NonZero::new(CACHE_SIZE).unwrap(),
            ))),
            rpc_type,
            _phantom: std::marker::PhantomData,
        }
    }

    pub async fn get_provider(&self) -> Result<ProviderGuard<ProviderT>, anyhow::Error> {
        Ok(ProviderGuard {
            provider: self.provider.clone(),
            _permit: self.semaphore.acquire().await?,
        })
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

            self.blocks_by_number
                .lock()
                .await
                .put(block.header.number, block.clone());
            self.blocks_by_hash
                .lock()
                .await
                .put(block.header.hash, block.header.number);

            Ok(block)
        }
    }
}

impl<ProviderT, TransportT> BlockProvider for CachedProvider<ProviderT, TransportT>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    async fn get_block_by_id(&self, block_id: BlockId) -> anyhow::Result<Option<Block>> {
        Ok(Some(
            self.get_block(block_id, BlockTransactionsKind::Hashes)
                .await?,
        ))
    }

    async fn latest_block_number(&self) -> anyhow::Result<u64> {
        Ok(self.provider.get_block_number().await?)
    }
}
