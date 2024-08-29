## Prover input format

The initial state of each trie is given by the prover as a
nondeterministic input tape. This tape has a slightly different format:

1.  An empty node is encoded as $(\texttt{MPT\_NODE\_EMPTY})$.

2.  A branch node is encoded as
    $(\texttt{MPT\_NODE\_BRANCH}, v_?, c_1, \dots, c_{16})$. Here $v_?$
    consists of a flag indicating whether a value is present, followed
    by the actual value payload if one is present. Each $c_i$ is the
    encoding of a child node.

3.  An extension node is encoded as
    $(\texttt{MPT\_NODE\_EXTENSION}, k, c)$, where $k$ represents the
    part of the key associated with this extension, and is encoded as a
    2-tuple $(\texttt{packed\_nibbles}, \texttt{num\_nibbles})$. $c$ is
    a pointer to a child node.

4.  A leaf node is encoded as $(\texttt{MPT\_NODE\_LEAF}, k, v)$, where
    $k$ is a 2-tuple as above, and $v$ is a value payload.

5.  A digest node is encoded as $(\texttt{MPT\_NODE\_HASH}, d)$, where
    $d$ is a Keccak256 digest.

Nodes are thus given in depth-first order, enabling natural recursive
methods for encoding and decoding this format. The payload of state and
receipt tries is given in the natural sequential way. The transaction an
receipt payloads contain variable size data, thus the input is slightly
different. The prover input for for the transactions is the transaction
RLP encoding preceded by its length. For the receipts is in the natural
sequential way, except that topics and data are preceded by their
lengths, respectively.
