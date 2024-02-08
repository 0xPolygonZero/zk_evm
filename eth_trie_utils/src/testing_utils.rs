use std::{
    collections::HashSet,
    iter::{once, repeat},
};

use ethereum_types::{H256, U256, U512};
use log::info;
use rand::{rngs::StdRng, seq::IteratorRandom, Rng, RngCore, SeedableRng};

use crate::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
    trie_ops::ValOrHash,
    utils::is_even,
};

/// Some tests check that all values inserted are retrievable, and if we end up
/// generating multiple inserts for the same key, then these tests will fail.
/// Making the min key nibbles sufficiently high will significantly decrease the
/// chances of these collisions occurring.
const MIN_BYTES_FOR_VAR_KEY: usize = 5;

pub(crate) type TrieType = HashedPartialTrie;

pub(crate) type TestInsertValEntry = (Nibbles, Vec<u8>);
pub(crate) type TestInsertHashEntry = (Nibbles, H256);
type TestInsertEntry<T> = (Nibbles, T);

// Don't want this exposed publicly, but it is useful for testing.
impl From<i32> for Nibbles {
    fn from(k: i32) -> Self {
        let packed = U512::from(k);

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

pub(crate) fn entry<K>(k: K) -> TestInsertValEntry
where
    K: Into<Nibbles>,
{
    (k.into(), vec![2])
}

/// Needed when replacing nodes with `Hash` nodes to ensure they are >= 32
/// bytes when RLP encoded.
pub(crate) fn large_entry<K>(k: K) -> TestInsertValEntry
where
    K: Into<Nibbles>,
{
    (k.into(), once(2).chain(repeat(255).take(32)).collect())
}

pub(crate) fn entry_with_value<K>(k: K, v: u8) -> TestInsertValEntry
where
    K: Into<Nibbles>,
{
    (k.into(), vec![v])
}

pub(crate) fn generate_n_random_fixed_trie_value_entries(
    n: usize,
    seed: u64,
) -> impl Iterator<Item = TestInsertValEntry> {
    gen_n_random_trie_value_entries_common(n, seed, gen_fixed_nibbles, gen_rand_u256_bytes)
}

pub(crate) fn generate_n_random_fixed_trie_hash_entries(
    n: usize,
    seed: u64,
) -> impl Iterator<Item = TestInsertHashEntry> {
    gen_n_random_trie_value_entries_common(n, seed, gen_fixed_nibbles, |_| H256::random())
}

pub(crate) fn generate_n_random_variable_trie_value_entries(
    n: usize,
    seed: u64,
) -> impl Iterator<Item = TestInsertValEntry> {
    gen_n_random_trie_value_entries_common(n, seed, gen_variable_nibbles, gen_rand_u256_bytes)
}

pub(crate) fn generate_n_random_fixed_even_nibble_padded_trie_value_entries(
    n: usize,
    seed: u64,
) -> impl Iterator<Item = TestInsertValEntry> {
    gen_n_random_trie_value_entries_common(
        n,
        seed,
        gen_variable_nibbles_even_padded_nibbles,
        gen_rand_u256_bytes,
    )
}

fn gen_n_random_trie_value_entries_common<
    T,
    K: Fn(&mut StdRng) -> Nibbles,
    V: Fn(&mut StdRng) -> T,
>(
    n: usize,
    seed: u64,
    key_gen_f: K,
    val_gen_f: V,
) -> impl Iterator<Item = TestInsertEntry<T>> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n).map(move |_| (key_gen_f(&mut rng), val_gen_f(&mut rng)))
}

pub(crate) fn generate_n_hash_nodes_entries_for_empty_slots_in_trie<N: PartialTrie>(
    trie: &Node<N>,
    n: usize,
    seed: u64,
) -> Vec<TestInsertHashEntry> {
    let mut rng = StdRng::seed_from_u64(seed);

    // Pretty inefficient, but ok for tests.
    trie.trie_items()
        .filter(|(k, v)| k.count <= 63 && matches!(v, ValOrHash::Val(_)))
        .map(|(k, _)| k.merge_nibble(1))
        .choose_multiple(&mut rng, n)
        .into_iter()
        .map(|k| (k, rng.gen()))
        .collect()
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
pub(crate) fn get_non_hash_values_in_trie<N: PartialTrie>(
    trie: &Node<N>,
) -> HashSet<TestInsertValEntry> {
    info!("Collecting all entries inserted into trie...");
    trie.trie_items()
        .map(|(k, v)| (k, v.expect_val()))
        .collect()
}

pub(crate) fn unwrap_iter_item_to_val(item: ValOrHash) -> Vec<u8> {
    match item {
        ValOrHash::Val(v) => v,
        ValOrHash::Hash(_) => unreachable!(),
    }
}

fn gen_rand_u256_bytes(rng: &mut StdRng) -> Vec<u8> {
    let num_bytes = 256 / 8;

    let mut buf = vec![0; num_bytes];
    rng.fill_bytes(&mut buf);

    buf
}

/// Initializes a trie with keys large enough to force hashing (nodes less than
/// 32 bytes are not hashed).
pub(crate) fn create_trie_with_large_entry_nodes<T: Into<Nibbles> + Copy>(keys: &[T]) -> TrieType {
    let mut trie = TrieType::default();
    for (k, v) in keys.iter().map(|k| (*k).into()).map(large_entry) {
        trie.insert(k, v.clone());
    }

    trie
}

pub(crate) fn handmade_trie_1() -> (TrieType, Vec<Nibbles>) {
    let ks = vec![0x1234, 0x1324, 0x132400005_u64, 0x2001, 0x2002];
    let ks_nibbles: Vec<Nibbles> = ks.into_iter().map(|k| k.into()).collect();
    let trie = create_trie_with_large_entry_nodes(&ks_nibbles);

    // Branch (0x)  --> 1, 2
    // Branch (0x1) --> 2, 3
    // Leaf (0x1234) --> (n: 0x34, v: [0])

    // Extension (0x13) --> n: 0x24
    // Branch (0x1324, v: [1]) --> 0
    // Leaf (0x132400005) --> (0x0005, v: [2])

    // Extension (0x2) --> n: 0x00
    // Branch (0x200) --> 1, 2
    // Leaf  (0x2001) --> (n: 0x1, v: [3])
    // Leaf  (0x2002) --> (n: 0x2, v: [4])

    (trie, ks_nibbles)
}
