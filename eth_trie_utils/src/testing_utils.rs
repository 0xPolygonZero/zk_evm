use ethereum_types::U256;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{partial_trie::Nibbles, trie_builder::InsertEntry, utils::is_even};

/// Some tests check that all values inserted are retrievable, and if we end up
/// generating multiple inserts for the same key, then these tests will fail.
/// Making the min key nibbles sufficiently high will significantly decrease the
/// chances of these collisions occurring.
const MIN_NIBBLES_FOR_VAR_KEY: usize = 10;

pub(crate) fn common_setup() {
    // Try init since multiple tests calling `init` will cause an error.
    let _ = pretty_env_logger::try_init();
}

pub(crate) fn trie_key(k: u64) -> U256 {
    U256::from(k)
}

pub(crate) fn empty_entry_fixed<K: Into<U256>>(k: K) -> InsertEntry {
    empty_entry_common(Nibbles::from_u256_fixed(k.into()))
}

pub(crate) fn empty_entry_variable<K: Into<U256>>(k: K) -> InsertEntry {
    empty_entry_common(Nibbles::from_u256_variable(k.into()))
}

fn empty_entry_common(nibbles: Nibbles) -> InsertEntry {
    InsertEntry {
        nibbles,
        v: vec![2],
    }
}

pub(crate) fn generate_n_random_fixed_trie_entries(
    n: usize,
    seed: u64,
) -> impl Iterator<Item = InsertEntry> {
    gen_n_random_trie_entries_common(n, seed, gen_fixed_u256)
}

pub(crate) fn generate_n_random_variable_keys(
    n: usize,
    seed: u64,
) -> impl Iterator<Item = InsertEntry> {
    gen_n_random_trie_entries_common(n, seed, gen_variable_u256)
}

fn gen_n_random_trie_entries_common<F: Fn(&mut StdRng) -> U256>(
    n: usize,
    seed: u64,
    u256_gen_f: F,
) -> impl Iterator<Item = InsertEntry> {
    let mut rng = StdRng::seed_from_u64(seed);

    (0..n).into_iter().map(move |i| {
        let nibbles = Nibbles::from_u256_variable(u256_gen_f(&mut rng));
        InsertEntry {
            nibbles,
            v: i.to_be_bytes().to_vec(),
        }
    })
}

fn gen_fixed_u256(rng: &mut StdRng) -> U256 {
    let mut k_bytes = [0; 4];
    k_bytes[0..3].copy_from_slice(rng.gen::<[u64; 3]>().as_slice());
    k_bytes[3] = rng.gen_range(0x1000_0000_0000_0000..0xffff_ffff_ffff_ffff);

    U256(k_bytes)
}

fn gen_variable_u256(rng: &mut StdRng) -> U256 {
    let n_nibbles = rng.gen_range(MIN_NIBBLES_FOR_VAR_KEY..=64);
    let n_bytes = n_nibbles / 2;

    let mut bytes = [0; 32];
    for b in bytes.iter_mut().take(n_bytes) {
        *b = rng.gen();
    }

    if !is_even(n_nibbles) {
        bytes[n_bytes] = rng.gen::<u8>() & 0x0f;
    }

    U256::from_little_endian(&bytes)
}

pub(crate) fn gen_u256(rng: &mut StdRng) -> U256 {
    U256(rng.gen())
}
