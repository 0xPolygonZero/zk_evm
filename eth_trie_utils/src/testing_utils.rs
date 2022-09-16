use ethereum_types::U256;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{partial_trie::Nibbles, trie_builder::TrieEntry, types::EthAddress};

pub(crate) fn nibbles(addr: u64) -> Nibbles {
    eth_addr(addr).into()
}

pub(crate) fn eth_addr(addr: u64) -> EthAddress {
    EthAddress::from(addr)
}

pub(crate) fn generate_n_random_trie_entries(n: usize) -> impl Iterator<Item = TrieEntry> {
    let mut rng = StdRng::seed_from_u64(0);

    (0..n).into_iter().map(move |i| {
        let nibbles = U256(rng.gen::<[u64; 4]>()).into();
        TrieEntry {
            nibbles,
            v: i.to_be_bytes().to_vec(),
        }
    })
}
