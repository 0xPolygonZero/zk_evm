## Linked lists

Individual account information are contained in the state and the
storage MPTs. However, accessing and modifying MPT data requires heavy
trie traversal, insertion and deletion functions. To alleviate these
costs, during an execution run, we store all account information in
linked list structures and only modify the state trie at the end of the
run.

Our linked list construction guarantees these properties:

-   A linked list is cyclic. The last element's successor is the first
    element.

-   A linked list is always sorted by a certain index, which can be one
    or more fields of an element.

-   The last element of a linked list is MAX, whose index is always
    higher than any possible index value.

-   An index cannot appear twice in the linked list.

These properties allows us to efficiently modify the list.

#### Search {#search .unnumbered}

To search a node given its index, we provide via `PROVER_INPUT` a
pointer to its predecessor $p$. We first check that $p$'s index is
strictly lower than the node index, if not, the provided pointer is
invalid. Then, we check $s$, $p$'s successor. If $s$'s index is equal to
the node index, we found the node. If $s$'s index is lower than the node
index, then the provided $p$ was invalid. If $s$'s index is greater than
the node index, then the node doesn't exist.

#### Insertion {#insertion .unnumbered}

To insert a node given its index, we provide via `PROVER_INPUT` a
pointer to its predecessor $p$. We first check that $p$'s index is
strictly lower than the node index, if not, the provided pointer is
invalid. Then, we check $s$, $p$'s successor, and make sure that $s$ is
strictly greater than the node index. We create a new node, and make it
$p$'s successor; then we make $s$ the new node's successor.

#### Deletion {#deletion .unnumbered}

To delete a node given its index, we provide via `PROVER_INPUT` a
pointer to its predecessor $p$. We check that $p$'s successor is equal
to the node index; if not either $p$ is invalid or the node doesn't
exist. Then we set $p$'s successor to the node's successor. To indicate
that the node is now deleted and to make sure that it's never accessed
again, we set its next pointer to MAX.

We maintain two linked lists: one for the state accounts and one for the
storage slots.

### Account linked list {#account-linked-list .unnumbered}

An account node is made of four memory cells:

-   The account key (the hash of the account address). This is the index
    of the node.

-   A pointer to the account payload, in segment `@TrieData`.

-   A pointer to the initial account payload, in segment `@TrieData`.
    This is the value of the account at the beginning of the execution,
    before processing any transaction. This payload never changes.

-   A pointer to the next node (which points to the next node's account
    key).

### Storage linked list {#storage-linked-list .unnumbered}

A storage node is made of five memory cells:

-   The account key (the hash of the account address).

-   The slot key (the hash of the slot). Nodes are indexed by
    `(account_key, slot_key)`.

-   The slot value.

-   The initial slot value. This is the value of the account at the
    beginning of the execution, before processing any transaction. It
    never changes.

-   A pointer to the next node (which points to the next node's account
    key).
