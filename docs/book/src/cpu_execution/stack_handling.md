## Stack handling {#stackhandling}

### Top of the stack

The majority of memory operations involve the stack. The stack is a
segment in memory, and stack operations (popping or pushing) use the
memory channels. Every CPU instruction performs between 0 and 3 pops,
and may push at most once. However, for efficiency purposes, we hold the
top of the stack in the first memory channel
`current_row.mem_channels[0]`, only writing it in memory if necessary.

#### Motivation: {#motivation .unnumbered}

See [this issue](https://github.com/0xPolygonZero/plonky2/issues/1149).

#### Top reading and writing: {#top-reading-and-writing .unnumbered}

When a CPU instruction modifies the stack, it must update the top of the
stack accordingly. There are three cases.

-   **The instruction pops and pushes:** The new top of the stack is
    stored in `next_row.mem_channels[0]`; it may be computed by the
    instruction, or it could be read from memory. In either case, the
    instruction is responsible for setting `next_row.mem_channels[0]`'s
    flags and address columns correctly. After use, the previous top of
    the stack is discarded and doesn't need to be written in memory.

-   **The instruction pushes, but doesn't pop:** The new top of the
    stack is stored in `next_row.mem_channels[0]`; it may be computed by
    the instruction, or it could be read from memory. In either case,
    the instruction is responsible for setting
    `next_row.mem_channels[0]`'s flags and address columns correctly. If
    the stack wasn't empty (`current_row.stack_len > 0`), the
    instruction performs a memory read in
    `current_row.partial_ channel`. `current_row.partial_channel` shares
    its values with `current_ row.mem_channels[0]` (which holds the
    current top of the stack). If the stack was empty,
    `current_row.partial_channel` is disabled.

-   **The instruction pops, but doesn't push:** After use, the current
    top of the stack is discarded and doesn't need to be written in
    memory. If the stack isn't empty now
    (`current_row.stack_len > num_pops`), the new top of the stack is
    set in `next_row.mem_channels[0]` with a memory read from the stack
    segment. If the stack is now empty, `next_row.mem_channels[0]` is
    disabled.

In the last two cases, there is an edge case if `current_row.stack_len`
is equal to a `special_len`. For a strictly pushing instruction, this
happens if the stack is empty, and `special_len = 0`. For a strictly
popping instruction, this happens if the next stack is empty, i.e. if
all remaining elements are popped, and `special_len = num_pops`. Note
that we do not need to check for values below `num_pops`, since this
would be a stack underflow exception which is handled separately. The
edge case is detected with the compound flag
$$\texttt{1 - not\_special\_len * stack\_inv\_aux,}$$ where
$$\texttt{not\_special\_len = current\_row - special\_len}$$

and `stack_inv_aux` is constrained to be the modular inverse of
`not_special_ len` if it's non-zero, or 0 otherwise. The flag is 1 if
`stack_len` is equal to `special_len`, and 0 otherwise.

This logic can be found in code in the `eval_packed_one` function of
[stack.rs](https://github.com/0xPolygonZero/plonky2/blob/main/evm/src/cpu/stack.rs).
The function multiplies all of the stack constraints with the degree 1
filter associated with the current instruction.

#### Operation flag merging: {#operation-flag-merging .unnumbered}

To reduce the total number of columns, many operation flags are merged
together (e.g. `DUP` and `SWAP`) and are distinguished with the binary
decomposition of their opcodes. The filter for a merged operation is now
of degree 2: for example, `is_swap = dup_swap * opcode_bits[4]` since
the 4th bit is set to 1 for a `SWAP` and 0 for a `DUP`. If the two
instructions have different stack behaviors, this can be a problem:
`eval_packed_one`'s constraints are already of degree 3 and it can't
support degree 2 filters.

When this happens, stack constraints are defined manually in the
operation's dedicated file (e.g. `dup_swap.rs`). Implementation details
vary case-by-case and can be found in the files.

### Stack length checking

The CPU must make sure that the stack length never goes below zero and,
in user mode, never grows beyond the maximum stack size. When this
happens, an honest prover should trigger the corresponding exception. If
a malicious prover doesn't trigger the exception, constraints must fail
the proof.

#### Stack underflow: {#stack-underflow .unnumbered}

There is no explicit constraint checking for stack underflow. An
underflow happens when the CPU tries to pop the empty stack, which would
perform a memory read at virtual address `-1`. Such a read cannot
succeed: in Memory, the range-check argument requires the gap between
two consecutive addresses to be lower than the length of the Memory
trace. Since the prime of the Plonky2 field is 64-bit long, this would
require a Memory trace longer than $2^{32}$.

#### Stack overflow: {#stack-overflow .unnumbered}

An instruction can only push at most once, meaning that an overflow
occurs whenever the stack length is exactly one more than the maximum
stack size ($1024+1$) in user mode. To constrain this, the column
`stack_len_bounds_aux` contains:

-   the modular inverse of `stack_len - 1025` if we're in user mode and
    `stack_len `$\neq$` 1025`,

-   0 if `stack_len = 1025` or if we're in kernel mode.

Then overflow can be checked with the flag
$$\texttt{(1 - is\_kernel\_mode) - stack\_len * stack\_len\_bounds\_aux}.$$
The flag is 1 if `stack_len = 1025` and we're in user mode, and 0
otherwise.

Because `stack_len_bounds_aux` is a shared general column, we only check
this constraint after an instruction that can actually trigger an
overflow, i.e. a pushing, non-popping instruction.
