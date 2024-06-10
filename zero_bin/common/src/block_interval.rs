use alloy::primitives::B256;
use alloy::rpc::types::eth::BlockId;
use alloy::{hex, providers::Provider, transports::Transport};
use anyhow::{anyhow, Result};
use async_stream::try_stream;
use futures::Stream;
use tracing::info;

use crate::parsing;

const DEFAULT_BLOCK_TIME: u64 = 1000;

/// Range of blocks to be processed and proven.
#[derive(Debug, PartialEq, Clone)]
pub enum BlockInterval {
    // A single block id (could be number or hash)
    SingleBlockId(BlockId),
    // A range of blocks.
    Range(std::ops::Range<u64>),
    // Dynamic interval from the start block to the latest network block
    FollowFrom {
        // Interval starting block number
        start_block: u64,
        // Block time specified in milliseconds.
        // If not set, use the default block time to poll node.
        block_time: Option<u64>,
    },
}

impl BlockInterval {
    /// Create a new block interval
    ///
    /// A valid block range is of the form:
    ///     * `block_number` for a single block number
    ///     * `lhs..rhs`, `lhs..=rhs` as an exclusive/inclusive range
    ///     * `lhs..` for a range starting from `lhs` to the chain tip. `lhs..=`
    ///       is also valid format.
    ///
    /// # Example
    ///
    /// ```rust
    ///    # use alloy::rpc::types::eth::BlockId;
    ///    # use common::block_interval::BlockInterval;
    ///    assert_eq!(BlockInterval::new("0..10").unwrap(), BlockInterval::Range(0..10));
    ///    assert_eq!(BlockInterval::new("0..=10").unwrap(), BlockInterval::Range(0..11));
    ///    assert_eq!(BlockInterval::new("32141").unwrap(), BlockInterval::SingleBlockId(BlockId::Number(32141.into())));
    ///    assert_eq!(BlockInterval::new("100..").unwrap(), BlockInterval::FollowFrom{start_block: 100, block_time: None});
    /// ```
    pub fn new(s: &str) -> anyhow::Result<BlockInterval> {
        if (s.starts_with("0x") && s.len() == 66) || s.len() == 64 {
            // Try to parse hash
            let hash = s
                .parse::<B256>()
                .map_err(|_| anyhow!("invalid block hash '{s}'"))?;
            return Ok(BlockInterval::SingleBlockId(BlockId::Hash(hash.into())));
        }

        // First we parse for inclusive range and then for exclusive range,
        // because both separators start with `..`
        if let Ok(range) = parsing::parse_range_inclusive(s) {
            Ok(BlockInterval::Range(range))
        } else if let Ok(range) = parsing::parse_range_exclusive(s) {
            Ok(BlockInterval::Range(range))
        }
        // Now we look for the follow from range
        else if s.contains("..") {
            let mut split = s.trim().split("..").filter(|s| *s != "=" && !s.is_empty());

            // Any other character after `..` or `..=` is invalid
            if split.clone().count() > 1 {
                return Err(anyhow!("invalid block interval range '{s}'"));
            }
            let num = split
                .next()
                .map(|num| {
                    num.parse::<u64>()
                        .map_err(|_| anyhow!("invalid block number '{num}'"))
                })
                .ok_or(anyhow!("invalid block interval range '{s}'"))??;
            return Ok(BlockInterval::FollowFrom {
                start_block: num,
                block_time: None,
            });
        }
        // Only single block number is left to try to parse
        else {
            let num: u64 = s
                .trim()
                .parse()
                .map_err(|_| anyhow!("invalid block interval range '{s}'"))?;
            return Ok(BlockInterval::SingleBlockId(BlockId::Number(num.into())));
        }
    }

    /// Convert the block interval into an async stream of block numbers.
    pub fn into_bounded_stream(self) -> anyhow::Result<impl Stream<Item = u64>> {
        match self {
            BlockInterval::SingleBlockId(BlockId::Number(num)) => {
                let num = num
                    .as_number()
                    .ok_or(anyhow!("invalid block number '{num}'"))?;
                Ok(futures::stream::iter(num..num + 1))
            }
            BlockInterval::Range(range) => Ok(futures::stream::iter(range)),
            _ => Err(anyhow!(
                "could not create bounded stream from unbounded follow-from interval",
            )),
        }
    }

    /// Convert the block interval into an unbounded async stream of block
    /// numbers. Query the blockchain node for the latest block number.
    pub async fn into_unbounded_stream<ProviderT, TransportT>(
        self,
        provider: ProviderT,
    ) -> Result<impl Stream<Item = Result<u64, anyhow::Error>>, anyhow::Error>
    where
        ProviderT: Provider<TransportT>,
        TransportT: Transport + Clone,
    {
        match self {
            BlockInterval::FollowFrom {
                start_block,
                block_time,
            } => Ok(try_stream! {
                let mut current = start_block;
                 loop {
                    let last_block_number = provider.get_block_number().await.map_err(|e: alloy::transports::RpcError<_>| {
                        anyhow!("could not retrieve latest block number from the provider: {e}")
                    })?;

                    if current < last_block_number {
                        current += 1;
                        yield current;
                    } else {
                       info!("Waiting for the new blocks to be mined, requested block number: {current}, \
                       latest block number: {last_block_number}");
                        let block_time = block_time.unwrap_or(DEFAULT_BLOCK_TIME);
                        // No need to poll the node too frequently, waiting
                        // a block time interval for a block to be mined should be enough
                       tokio::time::sleep(tokio::time::Duration::from_millis(block_time)).await;
                    }
                }
            }),
            _ => Err(anyhow!(
                "could not create unbounded follow-from stream from fixed bounded interval",
            )),
        }
    }
}

impl std::fmt::Display for BlockInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BlockInterval::SingleBlockId(block_id) => match block_id {
                BlockId::Number(it) => f.write_fmt(format_args!("{}", it)),
                BlockId::Hash(it) => f.write_fmt(format_args!("0x{}", &hex::encode(it.block_hash))),
            },
            BlockInterval::Range(range) => {
                write!(f, "{}..{}", range.start, range.end)
            }
            BlockInterval::FollowFrom { start_block, .. } => {
                write!(f, "{start_block}..")
            }
        }
    }
}

impl std::str::FromStr for BlockInterval {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BlockInterval::new(s)
    }
}

#[cfg(test)]
mod test {
    use alloy::primitives::B256;

    use super::*;

    #[test]
    fn can_create_block_interval_from_exclusive_range() {
        assert_eq!(
            BlockInterval::new("0..10").unwrap(),
            BlockInterval::Range(0..10)
        );
    }

    #[test]
    fn can_create_block_interval_from_inclusive_range() {
        assert_eq!(
            BlockInterval::new("0..=10").unwrap(),
            BlockInterval::Range(0..11)
        );
    }

    #[test]
    fn can_create_follow_from_block_interval() {
        assert_eq!(
            BlockInterval::new("100..").unwrap(),
            BlockInterval::FollowFrom {
                start_block: 100,
                block_time: None
            }
        );
    }

    #[test]
    fn can_create_single_block_interval() {
        assert_eq!(
            BlockInterval::new("123415131").unwrap(),
            BlockInterval::SingleBlockId(BlockId::Number(123415131.into()))
        );
    }

    #[test]
    fn new_interval_proper_single_block_error() {
        assert_eq!(
            BlockInterval::new("113A").err().unwrap().to_string(),
            "invalid block interval range '113A'"
        );
    }

    #[test]
    fn new_interval_proper_range_error() {
        assert_eq!(
            BlockInterval::new("111...156").err().unwrap().to_string(),
            "invalid block interval range '111...156'"
        );
    }

    #[test]
    fn new_interval_parse_block_hash() {
        assert_eq!(
            BlockInterval::new(
                "0xb51ceca7ba912779ed6721d2b93849758af0d2354683170fb71dead6e439e6cb"
            )
            .unwrap(),
            BlockInterval::SingleBlockId(BlockId::Hash(
                "0xb51ceca7ba912779ed6721d2b93849758af0d2354683170fb71dead6e439e6cb"
                    .parse::<B256>()
                    .unwrap()
                    .into()
            ))
        )
    }

    #[tokio::test]
    async fn can_into_bounded_stream() {
        use futures::StreamExt;
        let mut result = Vec::new();
        let mut stream = BlockInterval::new("1..10")
            .unwrap()
            .into_bounded_stream()
            .unwrap();
        while let Some(val) = stream.next().await {
            result.push(val);
        }
        assert_eq!(result, Vec::from_iter(1u64..10u64));
    }

    #[test]
    fn can_create_from_string() {
        use std::str::FromStr;
        assert_eq!(
            &format!("{}", BlockInterval::from_str("0..10").unwrap()),
            "0..10"
        );
    }
}
