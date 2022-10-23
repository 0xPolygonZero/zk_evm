use std::collections::HashSet;

use ethereum_types::U256;
use log::info;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{
    partial_trie::{Nibbles, PartialTrie},
    trie_ops::TrieIterItem,
    utils::is_even,
};

/// Some tests check that all values inserted are retrievable, and if we end up
/// generating multiple inserts for the same key, then these tests will fail.
/// Making the min key nibbles sufficiently high will significantly decrease the
/// chances of these collisions occurring.
const MIN_BYTES_FOR_VAR_KEY: usize = 5;

pub(crate) type TestInsertEntry = (Nibbles, Vec<u8>);

// Don't want this exposed publicly, but it is useful for testing.
impl From<U256> for Nibbles {
    fn from(packed: U256) -> Self {
        Self {
            count: Self::get_num_nibbles_in_key(&packed),
            packed,
        }
    }
}

// Also useful for testing.
impl From<u64> for Nibbles {
    fn from(k: u64) -> Self {
        let packed = U256::from(k);

        Self {
            count: Self::get_num_nibbles_in_key(&packed),
            packed,
        }
    }
}

// For testing...
impl From<Nibbles> for u64 {
    fn from(value: Nibbles) -> Self {
        value.packed.try_into().unwrap()
    }
}

pub(crate) fn common_setup() {
    // Try init since multiple tests calling `init` will cause an error.
    let _ = pretty_env_logger::try_init();
}

pub(crate) fn entry<K: Into<Nibbles>>(k: K) -> TestInsertEntry {
    (k.into(), vec![2])
}

pub(crate) fn entry_with_value<K: Into<Nibbles>>(k: K, v: u8) -> TestInsertEntry {
    (k.into(), vec![v])
}

pub(crate) fn generate_n_random_fixed_trie_entries(
    n: usize,
    seed: u64,
) -> impl Iterator<Item = TestInsertEntry> {
    gen_n_random_trie_entries_common(n, seed, gen_fixed_nibbles)
}

pub(crate) fn generate_n_random_variable_keys(
    n: usize,
    seed: u64,
) -> impl Iterator<Item = TestInsertEntry> {
    gen_n_random_trie_entries_common(n, seed, gen_variable_nibbles)
}

pub(crate) fn generate_n_random_fixed_even_nibble_padded_trie_entries(
    n: usize,
    seed: u64,
) -> impl Iterator<Item = TestInsertEntry> {
    gen_n_random_trie_entries_common(n, seed, gen_variable_nibbles_even_padded_nibbles)
}

fn gen_n_random_trie_entries_common<F: Fn(&mut StdRng) -> Nibbles>(
    n: usize,
    seed: u64,
    u256_gen_f: F,
) -> impl Iterator<Item = TestInsertEntry> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n)
        .into_iter()
        .map(move |i| (u256_gen_f(&mut rng), i.to_be_bytes().to_vec()))
}

fn gen_fixed_nibbles(rng: &mut StdRng) -> Nibbles {
    let mut k_bytes = [0; 4];
    k_bytes[0..3].copy_from_slice(rng.gen::<[u64; 3]>().as_slice());
    k_bytes[3] = rng.gen_range(0x1000_0000_0000_0000..0xffff_ffff_ffff_ffff);

    U256(k_bytes).into()
}

fn gen_variable_nibbles_even_padded_nibbles(rng: &mut StdRng) -> Nibbles {
    let mut n = gen_variable_nibbles(rng);
    if !is_even(n.count) {
        n.count += 1;
    }

    n
}

fn gen_variable_nibbles(rng: &mut StdRng) -> Nibbles {
    let n_bytes = rng.gen_range(MIN_BYTES_FOR_VAR_KEY..=32);

    let mut bytes = [0; 32];
    for b in bytes.iter_mut().take(n_bytes) {
        *b = rng.gen();
    }

    U256::from_little_endian(&bytes).into()
}

// TODO: Replace with `PartialTrie` `iter` methods once done...
pub(crate) fn get_entries_in_trie(trie: &PartialTrie) -> HashSet<TestInsertEntry> {
    info!("Collecting all entries inserted into trie...");
    trie.items()
        .map(|(k, v)| (k, unwrap_iter_item_to_val(v)))
        .collect()
}

pub(crate) fn unwrap_iter_item_to_val(item: TrieIterItem) -> Vec<u8> {
    match item {
        TrieIterItem::Value(v) => v,
        TrieIterItem::Hash(_) => unreachable!(),
    }
}
