## Byte Packing

The BytePacking STARK module is used for reading and writing non-empty
byte sequences of length at most 32 to memory. The \"packing\" term
highlights that reading a sequence in memory will pack the bytes into an
EVM word (i.e. U256), while the \"unpacking\" operation consists in
breaking down an EVM word into its byte sequence and writing it to
memory.

This allows faster memory copies between two memory locations, as well
as faster memory reset (see [memcpy.asm](https://github.com/0xPolygonZero/plonky2/blob/main/evm/src/cpu/kernel/asm/memory/memcpy.asm) and [memset.asm](https://github.com/0xPolygonZero/plonky2/blob/main/evm/src/cpu/kernel/asm/memory/memset.asm) modules).

The 'BytePackingStark' table has one row per packing/unpacking
operation.

Each row contains the following columns:

1.  5 columns containing information on the initial memory address from
    which the sequence starts (namely a flag differentiating read and
    write operations, address context, segment and offset values, as
    well as timestamp),

2.  32 columns $b_i$ indicating the length of the byte sequence
    ($b_i = 1$ if the length is $i+1$, and $b_i = 0$ otherwise),

3.  32 columns $v_i$ indicating the values of the bytes that have been
    read or written during a sequence,

4.  2 columns $r_i$ needed for range-checking the byte values.

#### Notes on columns generation

Whenever a byte unpacking operation is called, the value $\texttt{val}$
is read from the stack, but because the EVM and the STARKs use different
endianness, we need to convert $\texttt{val}$ to a little-endian byte
sequence. Only then do we resize it to the appropriate length, and prune
extra zeros and higher bytes in the process. Finally, we reverse the
byte order and write this new sequence into the $v_i$ columns of the
table.

Whenever the operation is a byte packing, the bytes are read one by one
from memory and stored in the $v_i$ columns of the BytePackingStark
table.

Note that because of the different endianness on the memory and EVM
sides, we write bytes starting with the last one.

The $b_i$ columns hold a boolean value. $b_i = 1$ whenever we are
currently reading or writing the i-th element in the byte sequence.
$b_i = 0$ otherwise.

#### Cross-table lookups

The read or written bytes need to be checked against both the cpu and
the memory tables. Whenever we call $\texttt{MSTORE\_32BYTES}$,
$\texttt{MLOAD\_32BYTES}$ or $\texttt{PUSH}$ on the cpu side, we make
use of 'BytePackingStark' to make sure we are carrying out the correct
operation on the correct values. For this, we check that the following
values correspond:

1.  the address (comprising the context, the segment, and the virtual
    address),

2.  the length of the byte sequence,

3.  the timestamp,

4.  the value (either written to or read from the stack)

The address here corresponds to the address of the first byte.

On the other hand, we need to make sure that the read and write
operations correspond to the values read or stored on the memory side.
We therefore need a CTL for each byte, checking that the following
values are identical in 'MemoryStark' and 'BytePackingStark':

1.  a flag indicating whether the operation is a read or a write,

2.  the address (context, segment and virtual address),

3.  the byte (followed by 0s to make sure the memory address contains a
    byte and not a U256 word),

4.  the timestamp

Note that the virtual address has to be recomputed based on the length
of the sequence of bytes. The virtual address for the $i$-th byte is
written as: $$\texttt{virt} + \sum_{j=0}^{31} b_j * j - i$$ where
$\sum_{j=0}^{31} b_j * j$ is equal to $\texttt{sequence\_length} - 1$.

#### Note on range-check

Range-checking is necessary whenever we do a memory unpacking operation
that will write values to memory. These values are constrained by the
range-check to be 8-bit values, i.e. fitting between 0 and 255 included.
While range-checking values read from memory is not necessary, because
we use the same $\texttt{byte\_values}$ columns for both read and write
operations, this extra condition is enforced throughout the whole trace
regardless of the operation type.
