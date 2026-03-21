# hbpf

A Haskell eDSL for writing eBPF programs with compile-time safety guarantees.

hbpf leverages Haskell's type system, purity, and static verification to produce correct eBPF bytecode — shifting the burden of correctness from the kernel verifier to the compiler. The goal is for eBPF programs to be written directly in Haskell rather than C, with the type system enforcing invariants that would otherwise only be caught at load time by the in-kernel verifier.

## Architecture

The library is built in layers:

**Layer 1 — Instruction Set (RFC 9669)**
A complete, typed encoding of the eBPF instruction set as defined in [RFC 9669](https://www.rfc-editor.org/rfc/rfc9669.html). This includes all ALU, jump, load/store, atomic, and byte-swap operations, along with binary encoding to bytecode.

**Layer 2 — Program Builder** *(current focus)*
A monadic DSL for composing full eBPF programs. Provides symbolic labels, automatic jump offset resolution, helper function calls, and a clean API that assembles down to a flat instruction stream. This is where most development is happening.

**Layer 3 — Kernel Integration** *(planned)*
Loading compiled programs into the kernel, map support, and program type enforcement.

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

## Building

```
cabal build
cabal test
```

Requires GHC 9.6+.

## Status

This is an active research project. Layer 2 (program construction) is functional and covers the full eBPF instruction set including atomics, wide loads, and all jump variants. The next step is kernel loading and map support. See [docs/why.md](docs/why.md) for the motivation and research direction.

## License

See [LICENSE](LICENSE).
