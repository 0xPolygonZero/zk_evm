## KeccakSponge {#keccak-sponge}

This table computes the Keccak256 hash, a sponge-based hash built on top
of the Keccak-f\[1600\] permutation. An instance of KeccakSponge takes
as input a Memory address $a$, a length $l$, and computes the Keccak256
digest of the memory segment starting at $a$ and of size $l$. An
instance can span many rows, each individual row being a single call to
the Keccak table. Note that all the read elements must be bytes; the
proof will be unverifiable if this is not the case. Following the Keccak
specifications, the input string is padded to the next multiple of 136
bytes. Each row contains the following columns:

-   Read bytes:

    -   3 address columns: `context`, `segment` and the offset `virt` of
        $a$.

    -   `timestamp`: the timestamp which will be used for all memory
        reads of this instance.

    -   `already_absorbed_bytes`: keeps track of how many bytes have
        been hashed in the current instance. At the end of an instance,
        we should have absorbed $l$ bytes in total.

    -   `KECCAK_RATE_BYTES` `block_bytes` columns: the bytes being
        absorbed at this row. They are read from memory and will be
        XORed to the rate part of the current state.

-   Input columns:

    -   `KECCAK_RATE_U32S` `original_rate_u32s` columns: hold the rate
        part of the state before XORing it with `block_bytes`. At the
        beginning of an instance, they are initialized with 0.

    -   `KECCAK_RATE_U32s` `xored_rate_u32s` columns: hold the original
        rate XORed with `block_bytes`.

    -   `KECCAK_CAPACITY_U32S` `original_capacity_u32s` columns: hold
        the capacity part of the state before applying the Keccak
        permutation.

-   Output columns:

    -   `KECCAK_DIGEST_BYTES` `updated_digest_state_bytes columns`: the
        beginning of the output state after applying the Keccak
        permutation. At the last row of an instance, they hold the
        computed hash. They are decomposed in bytes for endianness
        reasons.

    -   `KECCAK_WIDTH_MINUS_DIGEST_U32S` `partial_updated_state_u32s`
        columns: the rest of the output state. They are discarded for
        the final digest, but are used between instance rows.

-   Helper columns:

    -   `is_full_input_block`: indicates if the current row has a full
        input block, i.e. `block_bytes` contains only bytes read from
        memory and no padding bytes.

    -   `KECCAK_RATE_BYTES` `is_final_input_len` columns: in the final
        row of an instance, indicate where the final read byte is. If
        the $i$-th column is set to 1, it means that all bytes after the
        $i$-th are padding bytes. In a full input block, all columns are
        set to 0.

For each instance, constraints ensure that:

-   at each row:

    -   `is_full_input_block` and `is_final_input_len` columns are all
        binary.

    -   Only one column in `is_full_input_block` and
        `is_final_input_len` is set to 1.

    -   `xored_rate_u32s` is `original_rate_u32s` XOR `block_bytes`.

    -   The CTL with Keccak ensures that
        (`updated_digest_state_bytes columns`,
        `partial_updated_state_u32s`) is the Keccak permutation output
        of (`xored_rate_u32s`, `original_capacity_u32s`).

-   at the first row:

    -   `original_rate_u32s` is all 0.

    -   `already_absorbed_bytes` is 0.

-   at each full input row (i.e. `is_full_input_block` is 1, all
    `is_final_input_len` columns are 0):

    -   `context`, `segment`, `virt` and `timestamp` are unchanged in
        the next row.

    -   Next `already_absorbed_bytes` is current
        `already_absorbed_bytes` + `KECCAK_RATE_BYTES`.

    -   Next (`original_rate_u32s`, `original_capacity_u32s`) is current
        (`updated_digest_state_bytes columns`,
        `partial_updated_state_u32s`).

    -   The CTL with Memory ensures that `block_bytes` is filled with
        contiguous memory elements [$a$ + `already_absorbed_bytes`,
        $a$ + `already_absorbed_bytes` + `KECCAK_RATE_BYTES` - 1]

-   at the final row (i.e. `is_full_input_block` is 0,
    `is_final_input_len`'s $i$-th column is 1 for a certain $i$, the
    rest are 0):

    -   The CTL with Memory ensures that `block_bytes` is filled with
        contiguous memory elements [$a$ + `already_absorbed_bytes`,
        $a$ + `already_absorbed_bytes` + $i$ - 1]. The rest are padding
        bytes.

    -   The CTL with CPU ensures that `context`, `segment`, `virt` and
        `timestamp` match the `KECCAK_GENERAL` call.

    -   The CTL with CPU ensures that $l$ = `already_absorbed_bytes` +
        $i$.

    -   The CTL with CPU ensures that `updated_digest_state_bytes` is
        the output of the `KECCAK_GENERAL` call.

The trace is padded to the next power of two with dummy rows, whose
`is_full_input_block` and `is_final_input_len` columns are all 0.
