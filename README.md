# hbpf

A Haskell eDSL for writing eBPF programs with compile-time safety guarantees.

hbpf leverages Haskell's type system, purity, and static verification to produce correct eBPF bytecode — shifting the burden of correctness from the kernel verifier to the compiler. The goal is for eBPF programs to be written directly in Haskell, with the type system enforcing invariants that would otherwise only be caught at load time by the in-kernel verifier.

## Architecture

The library is built in layers:

**Layer 1 — Instruction Set (RFC 9669)** *(complete)*
A typed encoding of the eBPF instruction set as defined in [RFC 9669](https://www.rfc-editor.org/rfc/rfc9669.html). All ALU, jump, load/store, atomic, and byte-swap operations, along with binary encoding to bytecode.

**Layer 2 — Program Builder** *(complete)*
A monadic DSL for composing full eBPF programs. Symbolic labels, automatic jump offset resolution, helper function calls, and a clean API that assembles down to a flat instruction stream.

**Layer 3 — Higher-Level DSL & Kernel Integration** *(next)*
Stack management, typed map access, program type restrictions via phantom types, structured control flow, and kernel loading.

## Quick Example

```haskell
import Program
import Types

myProg :: BPF ()
myProg = do
  mov64 R1 (0 :: Int)
  mov64 R2 (1 :: Int)
  done <- newLabel
  jeq64 R1 R2 done
  add64 R1 (1 :: Int)
  label done
  mov64 R0 R1
  exit
```

For a complete Layer 2 real life example — an execve tracepoint that reads the PID, command name, and filename — see [app/Trace_execve.hs](app/Trace_execve.hs).

## Building

```
cabal build
cabal test
```

Requires GHC 9.6+.

## Status

This is an active research project. Layers 1 and 2 are complete — the full eBPF instruction set (including atomics, wide loads, and all jump variants) can be assembled into programs with symbolic labels and automatic offset resolution. The next step is Layer 3: typed map access, stack management, and kernel loading. See [docs/why.md](docs/why.md) for the motivation and research direction.

## License

See [LICENSE](LICENSE).
