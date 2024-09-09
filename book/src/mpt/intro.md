# Merkle Patricia Tries {#tries}

The *EVM World state* is a representation of the different accounts at a
particular time, as well as the last processed transactions together
with their receipts. The world state is represented using *Merkle
Patricia Tries* (MPTs, see [Yellowpaper App. D](@@yellowpaper)), and there are three
different tries: the state trie, the transaction trie and the receipt
trie.

For each transaction we need to show that the prover knows preimages of
the hashed initial and final EVM states. When the kernel starts
execution, it stores these three tries within the `Segment::TrieData`
segment. The prover loads the initial tries from the inputs into memory.
Subsequently, the tries are modified during transaction execution,
inserting new nodes or deleting existing nodes.

An MPT is composed of five different nodes: branch, extension, leaf,
empty and digest nodes. Branch and leaf nodes might contain a payload
whose format depends on the particular trie. The nodes are encoded,
primarily using RLP encoding and Hex-prefix encoding (see [Yellowpaper
App. B and C](@@yellowpaper), respectively). The resulting encoding is
then hashed, following a strategy similar to that of normal Merkle trees,
to generate the trie hashes.

Insertion and deletion is performed in the same way as other MPTs
implementations. The only difference is for inserting extension nodes
where we create a new node with the new data, instead of modifying the
existing one. In the rest of this section we describe how the MPTs are
represented in memory, how they are given as input, and how MPTs are
hashed.
