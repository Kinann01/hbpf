# Why hbpf

## The problem

eBPF programs are written in C, compiled with clang to bytecode, and loaded into the Linux kernel. Before execution, the kernel verifier walks every possible code path to prove the program is safe: no out-of-bounds memory access, no unbounded loops, no use of uninitialised data, no null pointer dereference without a check.

This is a runtime gate. You write your program, compile it, try to load it, and the verifier either accepts or rejects it. When it rejects, you get a verifier log — often cryptic, sometimes hundreds of lines — and you go back to your C code to figure out what went wrong. The feedback loop is slow and the failure modes are opaque.

The verifier exists because C gives no guarantees. The compiler doesn't know that a map lookup can return NULL and you must check it. It doesn't know that your loop bound is actually bounded. It doesn't know that the pointer you're reading from is within the packet boundary. So the kernel has to figure all of this out by itself, at load time, by brute-force analysis of the bytecode.

This is fundamentally a type system problem being solved without a type system.

## The goal

Haskell's type system can express most of the invariants the verifier checks. Instead of writing unsafe C and relying on a post-hoc bytecode verifier, we can write programs in a typed DSL where:

- A map lookup **returns `Maybe`** — you cannot use the value without pattern matching on it, so null checks are structural, not manual.
- Loop bounds are **encoded in the type** — a `BoundedFor n` runs exactly `n` iterations; the compiler proves termination.
- Stack allocation is **tracked statically** — the DSL knows the 512-byte limit and rejects programs that exceed it before any bytecode is generated.
- Program types **restrict which helpers are available** — an XDP program cannot call tracepoint helpers; this is a type error, not a verifier rejection.
- Memory access widths are **type-directed** — you cannot accidentally `ldx64` from a 4-byte field.

The goal is not to eliminate the verifier. It will always be the final authority. The goal is to **minimise interaction with it** — to produce bytecode that is correct by construction, so the verifier becomes a formality rather than the primary debugging tool.

## Where we are

### Layer 1 — Instruction encoding (complete)

A typed representation of every eBPF instruction as defined in RFC 9669. Opcodes, instruction constructors, binary encoding to bytecode. This is the foundation — it gives us a correct, tested way to produce eBPF bytecode from Haskell.

### Layer 2 — Program builder (current focus)

A monadic DSL for composing instructions into full programs with symbolic labels and automatic jump offset resolution. This is where you can write a program that looks like an assembler listing, but with the safety of Haskell's type system ensuring you don't misspell a register or forget to terminate. See [program.md](program.md) for details.

### Layer 3 — Where things get interesting (research)

This is the open question. Layer 2 gives you a typed assembler. Layer 3 is about raising the abstraction level so that more invariants are caught at compile time. Some of these ideas are well-understood; others are genuinely open research problems.

**Stack management.** Track stack allocation in the monad. `stackAlloc 256` returns a typed offset. The DSL knows how much stack is used and can reject programs that exceed 512 bytes at compile time rather than at verifier time.

**Typed map access.** Define maps at the type level with known key/value types and sizes. A lookup returns `Maybe (Ptr v)`, and you structurally cannot dereference it without handling the NULL case. This alone would eliminate one of the most common classes of verifier rejections.

**Register allocation.** Hide registers from the programmer entirely. Let users work with named bindings (`x <- getPidTgid`) and have the DSL assign registers, manage callee-save/restore around helper calls, and spill to stack when needed. The eBPF register file is small (11 registers, R10 is read-only) so even a simple allocator would work.

**Program type restrictions.** Use phantom types to distinguish program types at the type level. A `BPF XDP ()` can call `redirect`; a `BPF Tracepoint ()` cannot. A `BPF Kprobe ()` receives a `pt_regs` context; a `BPF SchedCls ()` receives `__sk_buff`. Wrong combinations become type errors.

**Structured control flow.** `if_`/`else_`, bounded loops, `switch`. These desugar to the existing label/jump machinery but prevent the programmer from constructing irreducible control flow or unbounded iteration — things the verifier would reject anyway.

**Context access.** Typed accessors for program-specific context structs. Instead of `ldx64 R0 R1 16` (what is offset 16?), something like `field <- readCtx @"args" 0` that knows the struct layout and emits the correct load at the correct offset and width.

**Kernel loading.** Actually loading the bytecode into the kernel — the `bpf()` syscall with `BPF_PROG_LOAD`, or FFI bindings to libbpf. Without this, programs can be assembled and inspected but not run.

## What this is not

This is not a Haskell-to-C transpiler. We are not generating C code and feeding it to clang. The DSL compiles directly to eBPF bytecode — the same format the kernel consumes. There is no intermediate C representation.

This is also not a general-purpose compiler. eBPF is a restricted execution environment: no heap, no recursion, bounded execution, limited stack. The DSL embraces these constraints rather than hiding them. The restriction is the feature — it's what makes static verification tractable.

## The bigger picture

eBPF is increasingly central to Linux infrastructure — networking (XDP, TC), observability (tracing, profiling), security (LSM, seccomp). The programs are small but critical: they run in kernel context on every packet, every syscall, every scheduler decision. Correctness matters.

The current toolchain (C + clang + verifier) works but pushes all safety checking to the last possible moment. Every property the verifier checks — null safety, bounds safety, termination, type correctness — is something a sufficiently expressive type system can check earlier and more clearly.

Haskell is not the obvious language for kernel programming. But it may be the right language for *specifying* kernel programs, because the things that make eBPF hard to write in C — restricted control flow, mandatory null checks, bounded resources, no dynamic allocation — are exactly the things Haskell's type system is good at encoding.

The question this project is trying to answer: **how much of the verifier's job can we move into the type checker?**
