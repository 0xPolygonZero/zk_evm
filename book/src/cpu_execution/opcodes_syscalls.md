## Simple opcodes & Syscalls

For simplicity and efficiency, EVM opcodes are categorized into two
groups: "simple opcodes" and "syscalls". Simple opcodes are generated
directly in Rust, in
[operation.rs](https://github.com/0xPolygonZero/plonky2/blob/main/evm/src/witness/operation.rs).
Every call to a simple opcode adds exactly one row to the [cpu
table](https://github.com/0xPolygonZero/plonky2/blob/main/evm/spec/tables/cpu.tex).
Syscalls are more complex structures written with simple opcodes, in the
kernel.

Whenever we encounter a syscall, we switch to kernel mode and execute
its associated code. At the end of each syscall, we run EXIT_KERNEL,
which resets the kernel mode to its state right before the syscall. It
also sets the PC to point to the opcode right after the syscall.

Exceptions are handled differently for simple opcodes and syscalls. When
necessary, simple opcodes throw an exception (see [exceptions](./exceptions.md)). This
activates the "exception flag" in the CPU and runs the exception
operations. On the other hand, syscalls handle exceptions in the kernel
directly.
