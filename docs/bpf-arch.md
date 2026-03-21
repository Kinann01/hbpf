## BPF Architecture

eBPF (extended Berkeley Packet Filter) is an in-kernel virtual machine that
lets programs run safely inside the Linux kernel without writing a kernel
module.  The major subsystems are:

- **Instruction set** — a RISC-like ISA (see `docs/instruction-set-demo.md`)
- **Maps** — shared key/value stores between BPF programs and user space
- **Helper functions** — kernel-defined functions BPF programs can call
- **Tail calls** — chain execution to another BPF program (up to 33 levels)
- **Verifier** — statically checks every program before it is allowed to run
- **BPF filesystem** — pins maps and programs so they outlive the loading process
- **JIT compiler** — translates BPF bytecode to native machine code at load time
- **Offload infrastructure** — allows BPF to run on hardware (e.g. SmartNICs)

LLVM provides a BPF backend, so `clang` can compile C into BPF object files
that are then loaded into the kernel.  This project takes a different approach:
programs are expressed directly in Haskell and assembled to BPF bytecode.

---

### Instruction Set

eBPF has a general-purpose RISC instruction set designed for writing programs in
a restricted subset of C, which LLVM compiles to BPF bytecode.  The kernel's
in-kernel JIT compiler then maps BPF bytecode to native opcodes.

**Advantages of running code inside the kernel:**

1. **No user/kernel boundary crossing** — BPF programs execute in kernel context.
   State can still be shared with user space through maps when needed.

2. **Flexibility** — programs can be heavily optimised for a specific use case
   (e.g. skip IPv6 processing when not needed).

3. **Atomic updates** — BPF programs can be swapped out at runtime without
   restarting the kernel.

4. **Stable ABI** — programs that run on one kernel version are guaranteed to
   run on newer kernels.  Programs are also portable across architectures.

5. **Safety** — the verifier enforces memory safety, termination, and type
   correctness before a program is allowed to run.  This is stronger than the
   guarantees provided by kernel modules.

**Registers:**  eBPF has eleven 64-bit registers (R0–R10) with 32-bit
sub-registers.  The 32-bit sub-registers zero-extend into 64 bits on write.
R10 is read-only and holds the frame pointer; all others are general-purpose.
The stack is 512 bytes.

The instruction limit is 1 million instructions.  Loops must be provably
finite (the verifier checks this).

**Calling convention:**

| Register | Role                                          |
|----------|-----------------------------------------------|
| R0       | Return value from helper calls and the program |
| R1–R5    | Arguments passed to helper functions           |
| R6–R9    | Callee-saved across helper calls               |
| R10      | Read-only frame pointer                        |

The BPF calling convention maps directly to x86-64, arm64, and other ABIs, so
a JIT compiler just needs to emit a native call instruction without extra moves.

The central `bpf()` system call manages all BPF operations: loading programs,
creating maps, looking up/updating/deleting map entries, and pinning objects in
the BPF filesystem.

See also:
- `kernel/include/uapi/linux/bpf_common.h`
- `docs/instruction-set-demo.md`

---

### Maps

Maps are generic key/value data structures.  They are created by user space and
shared with BPF programs (and with other user-space processes) through file
descriptors.  The kernel offers several map types: hash maps, arrays, per-CPU
variants, ring buffers, LRU maps, and more.

BPF programs interact with maps exclusively through helper functions
(`bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem`, etc.).

> **Project status:** map support is planned; see the project TODO.

---

### Helper Functions

Helper functions are the interface between BPF programs and the kernel.  Each
helper is a kernel-defined function callable via `BPF_CALL` with a helper ID.
The signature is:

```c
u64 fn(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
```

Arguments go in R1–R5; the return value comes back in R0.  Which helpers are
available depends on the BPF program type (e.g. socket programs have a
different set than TC programs).

In this project, `bpf_call helperID` emits the `BPF_CALL` instruction.  The
`helperID` corresponds to the `bpf_func_id` enum in the kernel headers.

> **Project status:** the `bpf_call` instruction and typed symbolic helper
> wrappers are implemented.  See `src/Helpers.hs` and `docs/bpf-helpers.md`.
