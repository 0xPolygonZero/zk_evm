//! Simple example showing off the basics of the library.

use std::iter::once;

use mpt_trie::partial_trie::PartialTrie;
use mpt_trie::utils::TryFromIterator;
use mpt_trie::{
    nibbles::{Nibbles, ToNibbles},
    partial_trie::{HashedPartialTrie, StandardTrie},
    trie_ops::{TrieOpResult, ValOrHash},
};

fn main() -> TrieOpResult<()> {
    // Construct an empty trie:
    let mut trie = StandardTrie::default();

    // Elements can be inserted into the trie by calling insert directly:
    trie.insert(
        Nibbles::from_bytes_be(b"hello").unwrap(),
        b"world!".to_vec(),
    )?;

    // Or by initializing the trie with an iterator of key value pairs:
    let mut trie = StandardTrie::try_from_iter(vec![
        (0x1234_u32, b"some data".to_vec()),
        (9001_u32, vec![1, 2, 3]),
    ])?;

    // Tries can be queried:
    assert_eq!(trie.get(0x1234_u32), Some(b"some data".as_slice()));
    assert_eq!(trie.get(0x5678_u32), None);

    // Trie hashes can be calculated:
    let _hash = trie.hash();

    // `PartialTrie` can produce iterators which iterate over the values it
    // contains:
    assert_eq!(
        trie.items().collect::<Vec<_>>(),
        vec![
            (0x1234_u32.into(), ValOrHash::Val(b"some data".to_vec())),
            (9001_u32.into(), ValOrHash::Val(vec![1, 2, 3]))
        ]
    );

    // Values can be deleted:
    let del_val = trie.delete(0x1234_u32)?;
    assert_eq!(del_val.unwrap(), b"some data".to_vec());
    assert_eq!(trie.get(0x1234_u32), None);

    // It's important to note how types are converted to `Nibbles`. This is
    // especially important if you are trying to get hashes that are in agreement
    // with a trie in an Ethereum EVM.
    //
    // By default, when converting to `Nibbles`, types are not padded to the nearest
    // byte. For example, `Nibbles::From(0x123)` does not becomes `0x0123`
    // internally. Many Ethereum trie libraries/EVM impls do this silently. If you
    // want to have identical hashes to an Ethereum trie, you will want to create
    // `Nibbles` like this instead:

    // Note that `From` just calls `to_nibbles` by default instead of
    // `to_nibbles_byte_padded`.
    let hash_1 = HashedPartialTrie::try_from_iter(once((
        0x19002_u32.to_nibbles_byte_padded(),
        vec![4, 5, 6],
    )))?
    .hash();
    let hash_2 =
        HashedPartialTrie::try_from_iter(once((0x19002_u32.to_nibbles(), vec![4, 5, 6])))?.hash();
    assert_ne!(hash_1, hash_2);

    // Finally note that `Nibbles` which are constructed from bytes are always
    // padded to the nearest byte:
    assert_eq!(
        format!("{:x}", Nibbles::from_bytes_be(&[1, 35, 69]).unwrap()),
        "0x012345"
    );
    assert_eq!(
        format!("{:x}", Nibbles::from_bytes_le(&[69, 35, 1]).unwrap()),
        "0x012345"
    );

    Ok(())
}
