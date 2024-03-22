//! Examples of constructing [`PartialTrie`]s for actual Ethereum tries.
//!
//! It's a bit difficult to ensure that nodes in Ethereum tries are RLP encoded
//! correctly. This library encodes keys being passed into the trie, but does
//! not apply any encoding to the values themselves.
//!
//! Also note that due to RLP encoding, the underlying integer types (with the
//! exception of hash types like `H256`) don't affect the hash generated due to
//! the RLP encoding truncating any leading zeros.

use std::ops::RangeInclusive;

use ethereum_types::{H160, H256, U256};
use keccak_hash::keccak;
use mpt_trie::partial_trie::PartialTrie;
use mpt_trie::trie_ops::TrieOpResult;
use mpt_trie::utils::TryFromIterator;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, StandardTrie},
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rlp::Encodable;
use rlp_derive::RlpEncodable;

const RANGE_OF_STORAGE_ENTRIES_AN_ACCOUNT_CAN_HAVE: RangeInclusive<usize> = 0..=10;
const NUM_ACCOUNTS_TO_GEN: usize = 100;

type HashedAccountAddr = H256;
type AccountAddr = H160;

/// Eth test account entry. As a separate struct to allow easy RLP encoding.
#[derive(Debug, RlpEncodable)]
struct StateTrieEntry {
    nonce: U256,
    balance: U256,
    storage_root: H256,
    code_hash: H256,
}

fn main() -> TrieOpResult<()> {
    let mut rng = StdRng::seed_from_u64(0);

    let generated: Result<Vec<_>, _> = (0..NUM_ACCOUNTS_TO_GEN)
        .map(|_| generate_fake_account_and_storage_trie(&mut rng))
        .collect();

    let (account_entries, account_storage_tries): (Vec<_>, Vec<_>) = match generated {
        Ok(pairs) => pairs.into_iter().unzip(),
        Err(e) => {
            return Err(e);
        }
    };

    let _state_trie = StandardTrie::try_from_iter(
        account_entries
            .into_iter()
            .map(|(k, acc)| (Nibbles::from_h256_be(k), acc.rlp_bytes().to_vec())),
    )?;

    let _account_storage_tries: Vec<(AccountAddr, HashedPartialTrie)> = account_storage_tries;

    Ok(())

    // TODO: Generate remaining tries...
}

fn generate_fake_account_and_storage_trie(
    rng: &mut StdRng,
) -> TrieOpResult<(
    (HashedAccountAddr, StateTrieEntry),
    (AccountAddr, HashedPartialTrie),
)> {
    let account_addr: H160 = rng.gen();
    let hashed_account_addr = keccak(account_addr.as_bytes());

    let account_storage_trie = generate_fake_account_storage_trie(rng)?;

    let acc_entry = StateTrieEntry {
        nonce: gen_u256(rng),
        balance: gen_u256(rng),
        storage_root: account_storage_trie.hash(),
        code_hash: rng.gen(), /* For the test, the contract code does not exist, so we can just
                               * "fake" it here. */
    };

    Ok((
        (hashed_account_addr, acc_entry),
        (account_addr, account_storage_trie),
    ))
}

fn generate_fake_account_storage_trie(rng: &mut StdRng) -> TrieOpResult<HashedPartialTrie> {
    let num_storage_entries = rng.gen_range(RANGE_OF_STORAGE_ENTRIES_AN_ACCOUNT_CAN_HAVE);

    Ok(HashedPartialTrie::try_from_iter(
        (0..num_storage_entries).map(|_| {
            let hashed_storage_addr = Nibbles::from_h256_be(rng.gen::<HashedAccountAddr>());
            let storage_data = gen_u256(rng).rlp_bytes().to_vec();

            (hashed_storage_addr, storage_data)
        }),
    )?)
}

fn gen_u256(rng: &mut StdRng) -> U256 {
    U256(rng.gen::<[u64; 4]>())
}
