## Kernel

The kernel is in charge of the proving logic. This section aims at
providing a high level overview of this logic. For details about any
specific part of the logic, one can consult the various "asm" files in
the ["kernel"
folder](https://github.com/0xPolygonZero/plonky2/tree/main/evm/src/cpu/kernel).

We prove a batch of transactions, split into segments. These proofs can
later be aggregated recursively to prove a block. Proof aggregation is
however not in the scope of this section. Here, we assume that we have
an initial state of the EVM, and we wish to prove that a batch of
contiguous transactions was correctly executed, leading to a correct
update of the state.

Since we process transactions and not entire blocks, a few intermediary
values need to be provided by the prover. Indeed, to prove that the
registers in the EVM state are correctly updated, we need to have access
to their initial values. When aggregating proofs, we can also constrain
those values to match from one batch to the next. Let us consider the
example of the transaction number. Let $n$ be the number of transactions
executed so far in the current block. If the current proof is not a
dummy one (we are indeed executing a batch of transactions), then the
transaction number should be updated: $n := n+k$ with $k$ the number of
transactions in the batch. Otherwise, the number remains unchanged. We
can easily constrain this update. When aggregating the previous
transaction batch proof ($lhs$) with the current one ($rhs$), we also
need to check that the output transaction number of $lhs$ is the same as
the input transaction number of $rhs$.

Those prover provided values are stored in memory prior to entering the
kernel, and are used in the kernel to assert correct updates. The list
of prover provided values necessary to the kernel is the following:

1.  the number of the last transaction executed: $t_n$,

2.  the gas used before executing the current transactions: $g\_u_0$,

3.  the gas used after executing the current transactions: $g\_u_1$,

4.  the state, transaction and receipts MPTs before executing the
    current transactions: $\texttt{tries}_0$,

5.  the hash of all MPTs before executing the current transactions:
    $\texttt{digests}_0$,

6.  the hash of all MPTs after executing the current transactions:
    $\texttt{digests}_1$,

7.  the RLP encoding of the transactions.

### Memory addresses {#memoryaddresses}

Kernel operations deal with memory addresses as single U256 elements.
However, when processing the operations to generate the proof witness,
the CPU will decompose these into three components:

-   The context of the memory address. The Kernel context is special,
    and has value 0.

-   The segment of the memory address, corresponding to a specific
    section given a context (eg. MPT data, global metadata, etc.).

-   The offset of the memory address, within a segment given a context.

To easily retrieve these components, we scale them so that they can
represent a memory address as:

$$\mathrm{addr} = 2^{64} \cdot \mathrm{context} + 2^{32} \cdot \mathrm{segment} + \mathrm{offset}$$

This allows to easily retrieve each component individually once a Memory
address has been decomposed into 32-bit limbs.

### Segment handling: {#segment-handling .unnumbered}

An execution run is split into one or more segments. To ensure
continuity, the first cycles of a segment are used to \"load\" segment
data from the previous segment, and the last cycles to \"save\" segment
data for the next segment. The number of CPU cycles of a segment is
bounded by `MAX_CPU_CYCLES`, which can be tweaked for best performance.
The segment data values are:

-   the stack length,

-   the stack top,

-   the context,

-   the `is_kernel` flag,

-   the gas used,

-   the program counter.

These values are stored as global metadata, and are loaded from (resp.
written to) memory at the beginning (resp. at the end) of a segment.
They are propagated between proofs as public values.

The initial memory of the first segment is fixed and contains:

-   the kernel code,

-   the shift table.

### Initialization: {#initialization .unnumbered}

The first step of a run consists in initializing:

-   The initial transaction and receipt tries $\texttt{tries}_0$ are
    loaded from memory. The transaction and the receipt tries are hashed
    and the hashes are then compared to $\texttt{digests}\_0$. For
    efficiency, the initial state trie will be hashed for verification
    at the end of the run.

-   We load the transaction number $t\_n$ and the current gas used
    $g\_u_0$ from memory.

We start processing the transactions (if any) sequentially, provided in
RLP encoded format.

The processing of the transaction returns a boolean "success" that
indicates whether the transaction was executed successfully, along with
the leftover gas.

The following step is then to update the receipts MPT. Here, we update
the transaction's bloom filter. We store "success", the leftover gas,
the transaction bloom filter and the logs in memory. We also store some
additional information that facilitates the RLP encoding of the receipts
later.

If there are any withdrawals, they are performed at this stage.

Finally, once the three MPTs have been updated, we need to carry out
final checks:

-   the gas used after the execution is equal to $g\_u_1$,

-   the new transaction number is $n + k$ with $k$ the number of
    processed transactions,

-   the initial state MPT is hashed and checked against
    $\texttt{digests}_0$.

-   the initial state MPT is updated to reflect the processed
    transactions, then the three final MPTs are hashed and checked
    against $\texttt{digests}_1$.

Once those final checks are performed, the program halts.