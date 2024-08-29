## Internal memory format

The tries are stored in kernel memory, specifically in the
`Segment:TrieData` segment. Each node type is stored as

1.  An empty node is encoded as $(\texttt{MPT\_NODE\_EMPTY})$.

2.  A branch node is encoded as
    $(\texttt{MPT\_NODE\_BRANCH}, c_1, \dots, c_{16}, v)$, where each
    $c_i$ is a pointer to a child node, and $v$ is a pointer to a value.
    If a branch node has no associated value, then $v = 0$, i.e. the
    null pointer.

3.  An extension node is encoded as
    $(\texttt{MPT\_NODE\_EXTENSION}, k, c)$, $k$ represents the part of
    the key associated with this extension, and is encoded as a 2-tuple
    $(\texttt{packed\_nibbles}, \texttt{num\_nibbles})$. $c$ is a
    pointer to a child node.

4.  A leaf node is encoded as $(\texttt{MPT\_NODE\_LEAF}, k, v)$, where
    $k$ is a 2-tuple as above, and $v$ is a pointer to a value.

5.  A digest node is encoded as $(\texttt{MPT\_NODE\_HASH}, d)$, where
    $d$ is a Keccak256 digest.

On the other hand the values or payloads are represented differently
depending on the particular trie.

### State trie

The state trie payload contains the account data. Each account is stored
in 4 contiguous memory addresses containing

1.  the nonce,

2.  the balance,

3.  a pointer to the account's storage trie,

4.  a hash of the account's code.

The storage trie payload in turn is a single word.

### Transaction Trie

The transaction trie nodes contain the length of the RLP encoded
transaction, followed by the bytes of the RLP encoding of the
transaction.

### Receipt Trie

The payload of the receipts trie is a receipt. Each receipt is stored as

1.  the length in words of the payload,

2.  the status,

3.  the cumulative gas used,

4.  the bloom filter, stored as 256 words.

5.  the number of topics,

6.  the topics

7.  the data length,

8.  the data.