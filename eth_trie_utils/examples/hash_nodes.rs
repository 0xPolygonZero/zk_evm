//! Example showing how to use `Hash` nodes.
//!
//!`Hash` nodes are used when you want to only want to represent part of a
//! larger trie but still want the generated hashes to be the same as the larger
//! trie. `Hash` nodes contain the merkle hash of the nodes of they replace.
//!
//! For example, say you want to generate a proof for a trie. The proof
//! itself only needs a very small subset of the values in the trie. However,
//! the trie still needs to be able to generate the same hash as the original
//! full trie. In order to have the `PartialTrie` generate the same hash, we
//! would replace the nodes that don't contain any children that we need with
//! `Hash` nodes.
//!
//! For example, say we only need the right hand side of the root:
//!
//! Full Trie:
//!```text
//!       N
//!    /    \
//!   B      B
//!  / \    / \
//! L   L  L   L
//! ```
//! Partial Trie:
//!```text
//!       B
//!    /    \
//!   H      B
//!         / \
//!        L   L
//! ```
//!
//! B --> Branch
//! H --> Hash
//! L --> Leaf
//!
//! Both tries generate the same hash since `Hash` nodes contain the merkle hash
//! of the nodes they replace.
//!
//! Note for simplicity, branches are shown to be binary here when in actuality
//! they are 16-ary.
//!
//! Finally, at least for the time being, it is assumed that if you are
//! converting a large partial trie into a `PartialTrie` then you are able to
//! calculate the hashes for the nodes you want to remove from the trie without
//! using this library.

use std::{
    iter::{once, repeat},
    str::FromStr,
};

use eth_trie_utils::{nibbles::Nibbles, partial_trie::PartialTrie};

fn main() {
    pretty_env_logger::try_init().unwrap();

    // Lets build the (binary) tries in the module-level docs. Since the example
    // uses binary nodes while branch nodes are really `16-ary`, we'll only use
    // branch slots `0` and `1`.
    let mut full_trie = PartialTrie::default();

    // Note the nibbles read the most significant nibble first (eg. `0x12` reads `1`
    // first).
    full_trie.insert(Nibbles::from_str("0x00").unwrap(), large_val(1)); // 1st from left.
    full_trie.insert(Nibbles::from_str("0x01").unwrap(), large_val(2)); // 2nd from left.
    full_trie.insert(Nibbles::from(0x10_u64), large_val(3)); // 3rd from left.
    full_trie.insert(Nibbles::from(0x11_u64), large_val(4)); // 4th from left.

    let full_trie_hash = full_trie.calc_hash();

    // Slight hack. Normally this has would come from your own logic that is making
    // calls into this crate to construct the `PartialTrie`. May add API to
    // do this in the future if needed.
    let left_side_hash = match &full_trie {
        PartialTrie::Branch { children, .. } => children[0].calc_hash(),
        _ => unreachable!(),
    };

    // Hash version. `0` branch is replaced with a `Hash` node.
    let mut hash_trie = PartialTrie::default();
    hash_trie.insert(Nibbles::from_str("0x0").unwrap(), left_side_hash); // Hash node
    hash_trie.insert(0x10_u64, large_val(3)); // 3rd from left.
    hash_trie.insert(0x11_u64, large_val(4)); // 4th from left.

    let hash_trie_hash = hash_trie.calc_hash();

    // Hashes should be equal.
    assert_eq!(full_trie_hash, hash_trie_hash);
}

/// We want to ensure that all leafs are >= 32 bytes when RLP encoded in order
/// to replace them with `Hash` nodes. Replacing a `PartialTrie` that is `<=` 32
/// bytes will lead to an incorrect hash being generated.
fn large_val(first_byte: u8) -> Vec<u8> {
    Vec::from_iter(once(first_byte).chain(repeat(255).take(32)))
}
