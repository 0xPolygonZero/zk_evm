# Ethereum Trie Utils

Currently a WIP and not the most performant.

Types and functions to work with Ethereum partial tries, which are identical to the tries described in the Ethereum yellow paper with the exception that nodes that we do not care about are replaced with `Hash` nodes. A `Hash` node just contains the merkle hash of the node it replaces.

As a concrete example, we may only care about the storage touched by a given txn. If we wanted to generate a `PartialTrie` for this, we would include the minimum number of nodes needed such that all of the storage addresses involved (leaves) are included in the partial trie. Since we may need to include `Branch` nodes, branch children that are not relevant for any of the storage of the txn are replaced with `Hash` nodes.
