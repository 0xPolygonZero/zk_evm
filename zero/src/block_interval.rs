use std::pin::Pin;
use std::sync::Arc;
use std::{future::Future, ops::Range};

use alloy::providers::Provider;
use alloy::rpc::types::BlockTransactionsKind;
use alloy::rpc::types::{eth::BlockId, Block};
use alloy::transports::Transport;
use anyhow::{anyhow, Result};
use async_stream::try_stream;
use futures::Stream;
#[cfg(test)]
use mockall::automock;
use tracing::info;

use crate::provider::CachedProvider;

#[cfg_attr(test, automock)]
pub trait BlockIntervalProvider {
    fn get_block_by_id(
        &self,
        block_id: BlockId,
    ) -> impl Future<Output = anyhow::Result<Option<Block>>> + Send;

    fn latest_block_number(&self) -> impl Future<Output = anyhow::Result<u64>> + Send;
}

impl<ProviderT, TransportT> BlockIntervalProvider for CachedProvider<ProviderT, TransportT>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    /// Retrieves block without transaction contents from the provider.
    async fn get_block_by_id(&self, block_id: BlockId) -> anyhow::Result<Option<Block>> {
        Ok(Some(
            self.get_block(block_id, BlockTransactionsKind::Hashes)
                .await?,
        ))
    }

    /// Retrieves the latest block number from the provider.
    async fn latest_block_number(&self) -> anyhow::Result<u64> {
        Ok(self.get_provider().await?.get_block_number().await?)
    }
}

/// The async stream of block numbers.
/// The second bool flag indicates if the element is last in the interval.
pub type BlockIntervalStream = Pin<Box<dyn Stream<Item = Result<(u64, bool), anyhow::Error>>>>;

/// Range of blocks to be processed and proven.
#[derive(Debug, PartialEq, Clone)]
pub enum BlockInterval {
    // A single block id (could be number or hash)
    SingleBlockId(u64),
    // A range of blocks.
    Range(Range<u64>),
    // Dynamic interval from the start block to the latest network block
    FollowFrom {
        // Interval starting block number
        start_block: u64,
    },
}

impl BlockInterval {
    /// Creates a new block interval.
    ///
    /// If end_block is None, the interval is unbounded and will follow from
    /// start_block. If start_block == end_block, the interval is a single
    /// block. Otherwise, the interval is an inclusive range from start_block to
    /// end_block.
    ///
    /// end_block is always treated as inclusive because it may have been
    /// specified as a block hash.
    pub async fn new(
        provider: Arc<impl BlockIntervalProvider>,
        start_block: BlockId,
        end_block: Option<BlockId>,
    ) -> Result<BlockInterval, anyhow::Error> {
        // Ensure the start block is a valid block number.
        let start_block_num = Self::block_to_num(provider.clone(), start_block).await?;

        // Create the block interval.
        match end_block {
            // Start and end are the same.
            Some(end_block) if end_block == start_block => {
                Ok(BlockInterval::SingleBlockId(start_block_num))
            }
            // Bounded range provided.
            Some(end_block) => {
                let end_block_num = Self::block_to_num(provider.clone(), end_block).await?;
                if end_block_num <= start_block_num {
                    return Err(anyhow!(
                        "invalid block interval range ({start_block_num}..{end_block_num})"
                    ));
                }
                Ok(BlockInterval::Range(start_block_num..end_block_num + 1))
            }
            // Unbounded range provided.
            None => Ok(BlockInterval::FollowFrom {
                start_block: start_block_num,
            }),
        }
    }

    /// Convert the block interval into an async stream of block numbers. The
    /// second bool flag indicates if the element is last in the interval.
    pub fn into_bounded_stream(self) -> Result<BlockIntervalStream, anyhow::Error> {
        match self {
            BlockInterval::SingleBlockId(num) => {
                let range = (num..num + 1).map(|it| Ok((it, true))).collect::<Vec<_>>();

                Ok(Box::pin(futures::stream::iter(range)))
            }
            BlockInterval::Range(range) => {
                let mut range = range.map(|it| Ok((it, false))).collect::<Vec<_>>();
                // Set last element indicator to true
                range.last_mut().map(|it| it.as_mut().map(|it| it.1 = true));
                Ok(Box::pin(futures::stream::iter(range)))
            }
            BlockInterval::FollowFrom { .. } => Err(anyhow!(
                "could not create bounded stream from unbounded follow-from interval",
            )),
        }
    }

    /// Returns the start block number of the interval.
    pub fn get_start_block(&self) -> Result<u64> {
        match self {
            BlockInterval::SingleBlockId(num) => Ok(*num),
            BlockInterval::Range(range) => Ok(range.start),
            BlockInterval::FollowFrom { start_block, .. } => Ok(*start_block),
        }
    }

    /// Convert the block interval into an unbounded async stream of block
    /// numbers. Query the blockchain node for the latest block number.
    pub async fn into_unbounded_stream(
        self,
        provider: Arc<impl BlockIntervalProvider + 'static>,
        block_time: u64,
    ) -> Result<BlockIntervalStream, anyhow::Error> {
        match self {
            BlockInterval::FollowFrom { start_block } => Ok(Box::pin(try_stream! {
                let mut current = start_block;
                 loop {
                    let last_block_number = provider.latest_block_number().await.map_err(|e| {
                        anyhow!("could not retrieve latest block number from the provider: {e}")
                    })?;

                    if current < last_block_number {
                        current += 1;
                        yield (current, false);
                    } else {
                       info!("Waiting for the new blocks to be mined, requested block number: {current}, \
                       latest block number: {last_block_number}");
                        // No need to poll the node too frequently, waiting
                        // a block time interval for a block to be mined should be enough
                       tokio::time::sleep(tokio::time::Duration::from_millis(block_time)).await;
                    }
                }
            })),
            _ => Err(anyhow!(
                "could not create unbounded follow-from stream from fixed bounded interval",
            )),
        }
    }

    /// Converts a [`BlockId`] into a block number by querying the provider.
    pub async fn block_to_num(
        provider: Arc<impl BlockIntervalProvider>,
        block: BlockId,
    ) -> Result<u64, anyhow::Error> {
        let block_num = match block {
            // Number already provided
            BlockId::Number(num) => num
                .as_number()
                .ok_or_else(|| anyhow!("invalid block number '{num}'"))?,

            // Hash provided, query the provider for the block number.
            BlockId::Hash(hash) => {
                let block = provider
                    .get_block_by_id(BlockId::Hash(hash))
                    .await
                    .map_err(|e| {
                        anyhow!("could not retrieve block number by hash from the provider: {e}")
                    })?;
                block
                    .ok_or(anyhow!("block not found {hash}"))?
                    .header
                    .number
            }
        };
        Ok(block_num)
    }
}

impl std::fmt::Display for BlockInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BlockInterval::SingleBlockId(num) => f.write_fmt(format_args!("{}", num)),
            BlockInterval::Range(range) => {
                write!(f, "{}..{}", range.start, range.end)
            }
            BlockInterval::FollowFrom { start_block, .. } => {
                write!(f, "{start_block}..")
            }
        }
    }
}

#[cfg(test)]
mod test {
    use alloy::primitives::B256;
    use alloy::rpc::types::{Block, Header, Transaction};
    use mockall::predicate::*;
    use MockBlockIntervalProvider;

    use super::*;

    #[tokio::test]
    async fn can_create_block_interval_from_inclusive_range() {
        assert_eq!(
            BlockInterval::new(
                Arc::new(MockBlockIntervalProvider::new()),
                BlockId::from(0),
                Some(BlockId::from(10))
            )
            .await
            .unwrap(),
            BlockInterval::Range(0..11)
        );
    }

    #[tokio::test]
    async fn can_create_follow_from_block_interval() {
        assert_eq!(
            BlockInterval::new(
                Arc::new(MockBlockIntervalProvider::new()),
                BlockId::from(100),
                None
            )
            .await
            .unwrap(),
            BlockInterval::FollowFrom { start_block: 100 }
        );
    }

    #[tokio::test]
    async fn can_create_single_block_interval() {
        assert_eq!(
            BlockInterval::new(
                Arc::new(MockBlockIntervalProvider::new()),
                BlockId::from(123415131),
                Some(BlockId::from(123415131))
            )
            .await
            .unwrap(),
            BlockInterval::SingleBlockId(123415131)
        );
    }

    #[tokio::test]
    async fn cannot_create_invalid_range() {
        assert_eq!(
            BlockInterval::new(
                Arc::new(MockBlockIntervalProvider::new()),
                BlockId::from(123415131),
                Some(BlockId::from(0))
            )
            .await
            .unwrap_err()
            .to_string(),
            anyhow!("invalid block interval range (123415131..0)").to_string()
        );
    }

    #[tokio::test]
    async fn can_create_single_block_interval_from_hash() {
        // Mock the block for single block interval.
        let mut mock = MockBlockIntervalProvider::new();
        let block_id = BlockId::Hash(
            "0xb51ceca7ba912779ed6721d2b93849758af0d2354683170fb71dead6e439e6cb"
                .parse::<B256>()
                .unwrap()
                .into(),
        );
        mock_block(&mut mock, block_id, 12345);

        // Create the interval.
        let mock = Arc::new(mock);
        assert_eq!(
            BlockInterval::new(mock, block_id, Some(block_id))
                .await
                .unwrap(),
            BlockInterval::SingleBlockId(12345)
        );
    }

    #[tokio::test]
    async fn can_create_block_interval_from_inclusive_hash_range() {
        // Mock the blocks for the range.
        let mut mock = MockBlockIntervalProvider::new();
        let start_block_id = BlockId::Hash(
            "0xb51ceca7ba912779ed6721d2b93849758af0d2354683170fb71dead6e439e6cb"
                .parse::<B256>()
                .unwrap()
                .into(),
        );
        mock_block(&mut mock, start_block_id, 12345);
        let end_block_id = BlockId::Hash(
            "0x351ceca7ba912779ed6721d2b93849758af0d2354683170fb71dead6e439e6cb"
                .parse::<B256>()
                .unwrap()
                .into(),
        );
        mock_block(&mut mock, end_block_id, 12355);

        // Create the interval.
        let mock = Arc::new(mock);
        assert_eq!(
            BlockInterval::new(mock, start_block_id, Some(end_block_id))
                .await
                .unwrap(),
            BlockInterval::Range(12345..12356)
        );
    }

    #[tokio::test]
    async fn can_create_follow_from_block_interval_hash() {
        // Mock a block for range to start from.
        let start_block_id = BlockId::Hash(
            "0xb51ceca7ba912779ed6721d2b93849758af0d2354683170fb71dead6e439e6cb"
                .parse::<B256>()
                .unwrap()
                .into(),
        );
        let mut mock = MockBlockIntervalProvider::new();
        mock_block(&mut mock, start_block_id, 12345);

        // Create the interval.
        let mock = Arc::new(mock);
        assert_eq!(
            BlockInterval::new(mock, start_block_id, None)
                .await
                .unwrap(),
            BlockInterval::FollowFrom { start_block: 12345 }
        );
    }

    /// Configures the mock to expect a query for a block by id and return the
    /// expected block number.
    fn mock_block(
        mock: &mut MockBlockIntervalProvider,
        query_id: BlockId,
        resulting_block_num: u64,
    ) {
        let mut block: Block<Transaction, Header> = Block::default();
        block.header.number = resulting_block_num;
        mock.expect_get_block_by_id()
            .with(eq(query_id))
            .returning(move |_| {
                let block = block.clone();
                Box::pin(async move { Ok(Some(block)) })
            });
    }

    #[tokio::test]
    async fn can_into_bounded_stream() {
        use futures::StreamExt;
        let mut result = Vec::new();
        let mut stream = BlockInterval::new(
            Arc::new(MockBlockIntervalProvider::new()),
            BlockId::from(1),
            Some(BlockId::from(9)),
        )
        .await
        .unwrap()
        .into_bounded_stream()
        .unwrap();
        while let Some(val) = stream.next().await {
            result.push(val.unwrap());
        }
        let mut expected = Vec::from_iter(1u64..10u64)
            .into_iter()
            .map(|it| (it, false))
            .collect::<Vec<_>>();
        expected.last_mut().unwrap().1 = true;
        assert_eq!(result, expected);
    }
}
