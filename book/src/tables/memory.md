## Memory

For simplicity, let's treat addresses and values as individual field
elements. The generalization to multi-element addresses and values is
straightforward.

Each row of the memory table corresponds to a single memory operation (a
read or a write), and contains the following columns:

1.  $a$, the target address

2.  $r$, an "is read" flag, which should be 1 for a read or 0 for a
    write

3.  $v$, the value being read or written

4.  $\tau$, the timestamp of the operation

The memory table should be ordered by $(a, \tau)$. Note that the
correctness of the memory could be checked as follows:

1.  Verify the ordering by checking that
    $(a_i, \tau_i) \leq (a_{i+1}, \tau_{i+1})$ for each consecutive
    pair.

2.  Enumerate the purportedly-ordered log while tracking the "current"
    value of $v$.

    1.  Upon observing an address which doesn't match that of the
        previous row, if the address is zero-initialized and if the
        operation is a read, check that $v = 0$.

    2.  Upon observing a write, don't constrain $v$.

    3.  Upon observing a read at timestamp $\tau_i$ which isn't the
        first operation at this address, check that $v_i = v_{i-1}$.

The ordering check is slightly involved since we are comparing multiple
columns. To facilitate this, we add an additional column $e$, where the
prover can indicate whether two consecutive addresses changed. An honest
prover will set $$e_i \leftarrow \begin{cases}
  1 & \text{if } a_i \neq a_{i + 1}, \\
  0 & \text{otherwise}.
\end{cases}$$ We also introduce a range-check column $c$, which should
hold: $$c_i \leftarrow \begin{cases}
  a_{i + 1} - a_i - 1 & \text{if } e_i = 1, \\
  \tau_{i+1} - \tau_i & \text{otherwise}.
\end{cases}$$ The extra $-1$ ensures that the address actually changed
if $e_i = 1$. We then impose the following transition constraints:

1.  $e_i (e_i - 1) = 0$,

2.  $(1 - e_i) (a_{i + 1} - a_i) = 0$,

3.  $c_i < 2^{32}$.

The third constraint emulates a comparison between two addresses or
timestamps by bounding their difference; this assumes that all addresses
and timestamps fit in 32 bits and that the field is larger than that.

### Virtual memory

In the EVM, each contract call has its own address space. Within that
address space, there are separate segments for code, main memory, stack
memory, calldata, and returndata. Thus each address actually has three
components:

1.  an execution context, representing a contract call,

2.  a segment ID, used to separate code, main memory, and so forth, and
    so on

3.  a virtual address.

The comparisons now involve several columns, which requires some minor
adaptations to the technique described above; we will leave these as an
exercise to the reader.

Note that an additional constraint check is required: whenever we change
the context or the segment, the virtual address must be range-checked to
$2^{32}$. Without this check, addresses could start at -1 (i.e. $p - 2$)
and then increase properly.

### Timestamps

Memory operations are sorted by address $a$ and timestamp $\tau$. For a
memory operation in the CPU, we have:
$$\tau = \texttt{NUM\_CHANNELS} \times \texttt{cycle} + \texttt{channel}.$$
Since a memory channel can only hold at most one memory operation, every
CPU memory operation's timestamp is unique.

Note that it doesn't mean that all memory operations have unique
timestamps. There are two exceptions:

-   Before the CPU cycles, we preinitialize the memory with the flashed
    state stored in the MemBefore table and we write some global
    metadata. These operations are done at timestamp $\tau = 0$.

-   Some tables other than CPU can generate memory operations, like
    KeccakSponge. When this happens, these operations all have the
    timestamp of the CPU row of the instruction which invoked the table
    (for KeccakSponge, KECCAK_GENERAL).

### Memory initialization

By default, all memory is zero-initialized. However, to save numerous
writes, we allow some specific segments to be initialized with arbitrary
values.

-   The code segment (segment 0) is either part of the initial memory
    for the kernel (context 0), or is initialized with
    externally-provided account code, then checked against the account
    code hash. In non-zero contexts, if the code is meant to be
    executed, there is a soundness concern: if the code is malformed and
    ends with an incomplete PUSH, then the missing bytes must be 0
    accordingly to the Ethereum specs. To prevent the issue, we manually
    write 33 zeros (at most 32 bytes for the PUSH argument, and an extra
    one for the post-PUSH PC value).

-   The "TrieData" segment is initialized with the input tries. The
    stored tries are hashed and checked against the provided initial
    hash. Note that the length of the segment and the pointers -- within
    the "TrieData" segment -- for the three tries are provided as prover
    inputs. The length is then checked against a value computed when
    hashing the tries.

### Final memory

The final value of each cell of the memory must be propagated to the
MemAfter table. Since memory operations are ordered by address and by
timestamps, this is easy to do: the last value of an address is the
value of the last row touching this address. In other words, we
propagate values of rows before the address changes.

#### Context pruning {#context-pruning}

We can observe that whenever we return from a context (e.g. with a
RETURN opcode, from an exception\...), we will never access it again and
all its memory is now stale. We make use of this fact to prune stale
contexts and exclude them from MemAfter.
