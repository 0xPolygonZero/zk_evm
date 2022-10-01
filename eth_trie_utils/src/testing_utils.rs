use ethereum_types::U256;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{partial_trie::Nibbles, trie_builder::InsertEntry};

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
    let mut rng = StdRng::seed_from_u64(seed);

    (0..n).into_iter().map(move |i| {
        let mut k_bytes = [0; 4];
        k_bytes[0..3].copy_from_slice(rng.gen::<[u64; 3]>().as_slice());
        k_bytes[3] = rng.gen_range(0x1000_0000_0000_0000..0xffff_ffff_ffff_ffff);

        let nibbles = Nibbles::from_u256_variable(U256(k_bytes));
        InsertEntry {
            nibbles,
            v: i.to_be_bytes().to_vec(),
        }
    })
}

pub(crate) fn gen_u256(rng: &mut StdRng) -> U256 {
    U256(rng.gen())
}
