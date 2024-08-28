## Encoding and Hashing

Encoding is done recursively starting from the trie root. Leaf, branch
and extension nodes are encoded as the RLP encoding of list containing
the hex prefix encoding of the node key as well as

- Leaf Node: the encoding of the the payload,

- Branch Node: the hash or encoding of the 16 children and the encoding of the payload,

- Extension Node: the hash or encoding of the child and the encoding of the payload.

For the rest of the nodes we have:

- Empty Node: the encoding of an empty node is `0x80`,

- Digest Node: the encoding of a digest node stored as $({\tt MPT\_HASH\_NODE}, d)$ is $d$.

The payloads in turn are RLP encoded as follows

- State Trie: Encoded as a list containing nonce, balance, storage trie hash and code hash.

- Storage Trie: The RLP encoding of the value (thus the double RLP encoding)

- Transaction Trie: The RLP encoded transaction.
- Receipt Trie: Depending on the transaction type, it is encoded as
    ${\sf RLP}({\sf RLP}({\tt receipt}))$ for Legacy transactions or
    ${\sf RLP}({\tt txn\_type}||{\sf RLP}({\tt receipt}))$ for
    transactions of type 1 or 2. Each receipt is encoded as a list
    containing:

    1.  the status,

    2.  the cumulative gas used,

    3.  the bloom filter, stored as a list of length 256.

    4.  the list of topics

    5.  the data string.

Once a node is encoded it is written to the `Segment::RlpRaw` segment as
a sequence of bytes. Then the RLP encoded data is hashed if the length
of the data is more than 32 bytes. Otherwise we return the encoding.
Further details can be found in the [mpt hash
module](https://github.com/0xPolygonZero/plonky2/tree/main/evm/src/cpu/mpt/hash).
