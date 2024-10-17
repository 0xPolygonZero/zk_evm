use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;

use alloy::rpc::types::eth::BlockId;
use alloy::rpc::types::BlockTransactionsKind;
use alloy::{hex, providers::Provider, transports::Transport};
use anyhow::{anyhow, Result};
use async_stream::try_stream;
use futures::Stream;
use tracing::info;

use crate::provider::CachedProvider;

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
    /// Create a new block interval.
    ///
    /// If end_block is None, the interval is unbounded and will follow from
    /// start_block. If start_block == end_block, the interval is a single
    /// block. Otherwise the interval is a range from start_block to end_block.
    pub async fn new<ProviderT, TransportT>(
        cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
        start_block: BlockId,
        end_block: Option<BlockId>,
    ) -> Result<BlockInterval, anyhow::Error>
    where
        ProviderT: Provider<TransportT> + 'static,
        TransportT: Transport + Clone,
    {
        // Ensure the start block is a valid block number.
        let start_block_num = Self::block_to_num(cached_provider.clone(), start_block).await?;

        // Create the block interval.
        match end_block {
            // Start and end are the same.
            Some(end_block) if end_block == start_block => {
                Ok(BlockInterval::SingleBlockId(start_block_num))
            }
            // Bounded range provided.
            Some(end_block) => {
                let end_block_num = Self::block_to_num(cached_provider.clone(), end_block).await?;
                Ok(BlockInterval::Range(start_block_num..end_block_num + 1))
            }
            // Unbounded range provided.
            None => {
                let start_block_num =
                    Self::block_to_num(cached_provider.clone(), start_block).await?;
                Ok(BlockInterval::FollowFrom {
                    start_block: start_block_num,
                })
            }
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

    pub fn get_start_block(&self) -> Result<u64> {
        match self {
            BlockInterval::SingleBlockId(num) => Ok(*num),
            BlockInterval::Range(range) => Ok(range.start),
            BlockInterval::FollowFrom { start_block, .. } => Ok(*start_block),
            _ => Err(anyhow!("Unknown BlockInterval variant")), // Handle unknown variants
        }
    }

    /// Convert the block interval into an unbounded async stream of block
    /// numbers. Query the blockchain node for the latest block number.
    pub async fn into_unbounded_stream<ProviderT, TransportT>(
        self,
        cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
        block_time: u64,
    ) -> Result<BlockIntervalStream, anyhow::Error>
    where
        ProviderT: Provider<TransportT> + 'static,
        TransportT: Transport + Clone,
    {
        match self {
            BlockInterval::FollowFrom { start_block } => Ok(Box::pin(try_stream! {
                let mut current = start_block;
                 loop {
                    let last_block_number = cached_provider.get_provider().await?.get_block_number().await.map_err(|e: alloy::transports::RpcError<_>| {
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

    pub async fn block_to_num<ProviderT, TransportT>(
        cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
        block: BlockId,
    ) -> Result<u64, anyhow::Error>
    where
        ProviderT: Provider<TransportT> + 'static,
        TransportT: Transport + Clone,
    {
        let block_num = match block {
            BlockId::Number(num) => num
                .as_number()
                .ok_or_else(|| anyhow!("invalid block number '{num}'"))?,
            BlockId::Hash(hash) => {
                let block = cached_provider
                    .get_provider()
                    .await?
                    .get_block(BlockId::Hash(hash), BlockTransactionsKind::Hashes)
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

// TODO(serge current PR): Add tests using mocks for CachedProvider
//#[cfg(test)]
//mod test {
//    use alloy::primitives::B256;
//
//    use super::*;
//
//    #[test]
//    fn can_create_block_interval_from_exclusive_range() {
//        assert_eq!(
//            BlockInterval::new(BlockId::from(0), BlockId::from(10)).unwrap(),
//            //BlockInterval::new("0..10").unwrap(),
//            BlockInterval::Range(0..10)
//        );
//    }
//
//    #[test]
//    fn can_create_block_interval_from_inclusive_range() {
//        assert_eq!(
//            BlockInterval::new("0..=10").unwrap(),
//            BlockInterval::Range(0..11)
//        );
//    }
//
//    #[test]
//    fn can_create_follow_from_block_interval() {
//        assert_eq!(
//            BlockInterval::new("100..").unwrap(),
//            BlockInterval::FollowFrom { start_block: 100 }
//        );
//    }
//
//    #[test]
//    fn can_create_single_block_interval() {
//        assert_eq!(
//            BlockInterval::new("123415131").unwrap(),
//            BlockInterval::SingleBlockId(BlockId::Number(123415131.into()))
//        );
//    }
//
//    #[test]
//    fn new_interval_proper_single_block_error() {
//        assert_eq!(
//            BlockInterval::new("113A").err().unwrap().to_string(),
//            "invalid block interval range '113A'"
//        );
//    }
//
//    #[test]
//    fn new_interval_proper_range_error() {
//        assert_eq!(
//            BlockInterval::new("111...156").err().unwrap().to_string(),
//            "invalid block interval range '111...156'"
//        );
//    }
//
//    #[test]
//    fn new_interval_parse_block_hash() {
//        assert_eq!(
//            BlockInterval::new(
//
// "0xb51ceca7ba912779ed6721d2b93849758af0d2354683170fb71dead6e439e6cb"
//            )
//            .unwrap(),
//            BlockInterval::SingleBlockId(BlockId::Hash(
//
// "0xb51ceca7ba912779ed6721d2b93849758af0d2354683170fb71dead6e439e6cb"
//                    .parse::<B256>()
//                    .unwrap()
//                    .into()
//            ))
//        )
//    }
//
//    #[tokio::test]
//    async fn can_into_bounded_stream() {
//        use futures::StreamExt;
//        let mut result = Vec::new();
//        let mut stream = BlockInterval::new("1..10")
//            .unwrap()
//            .into_bounded_stream()
//            .unwrap();
//        while let Some(val) = stream.next().await {
//            result.push(val.unwrap());
//        }
//        let mut expected = Vec::from_iter(1u64..10u64)
//            .into_iter()
//            .map(|it| (it, false))
//            .collect::<Vec<_>>();
//        expected.last_mut().unwrap().1 = true;
//        assert_eq!(result, expected);
//    }
//
//    #[test]
//    fn can_create_from_string() {
//        use std::str::FromStr;
//        assert_eq!(
//            &format!("{}", BlockInterval::from_str("0..10").unwrap()),
//            "0..10"
//        );
//    }
//}
