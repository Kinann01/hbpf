# Developer Notes

This document describes the internal architecture of the `hbpf` library and
explains how to extend it.  It is aimed at contributors who want to add new
instruction classes, fix bugs, or understand design decisions.

---

## Module Map

```
src/
  Types.hs               — all algebraic data types (registers, ops, instruction)
  Opcode.hs              — opcode byte constants and composition helpers
  GenericInstructions.hs — SourceType typeclass and generic instruction builders
  Instructions.hs        — public API (bpf_add64, bpf_jeq64, bpf_exit, …)
  Helpers.hs             — typed BPF helper function wrappers (map ops, tracing, …)
  Encode.hs              — binary encoding to ByteString.Builder (little-endian)
  Program.hs             — Layer 2 program builder monad (labels, jumps, assemble)
app/
  Main.hs                — example program
```

The data flow is:

```
user code (Instructions.hs API)
    ↓  calls
GenericInstructions.hs  (builders — pure functions)
    ↓  uses
Opcode.hs               (opcode composition via bitwise OR)
    ↓
Types.Instruction       (StandardInstruction | ExtendedInstruction)
    ↓
Encode.hs               (→ ByteString.Builder → lazy ByteString → file/socket)
```

---

## Key Design: `SourceType` Typeclass

Most ALU and JMP instructions accept either a register or a 32-bit immediate as
their second operand.  Instead of duplicating each function, a single typeclass
abstracts this:

```haskell
class SourceType t where
  getSrcBit :: t -> SrcType   -- BPF_X (register) or BPF_K (immediate)
  getSrcReg :: t -> Reg       -- source register, or R0 when immediate
  getImmVal :: t -> Int32     -- immediate value, or 0 when register

instance SourceType Reg where ...
instance SourceType Int where ...
```

A polymorphic function like `bpf_add64 :: (SourceType a) => Reg -> a -> Instruction`
then works for both:

```haskell
bpf_add64 R1 R2          -- register source
bpf_add64 R1 (42 :: Int) -- immediate source
```

---

## Opcode Composition

An eBPF opcode is a single byte assembled from three fields OR'd together:

```
For ALU / JMP:   opcode = operation_bits | source_bit | class_bits
For LD/ST:       opcode = mode_bits | size_bits | class_bits
```

`Opcode.hs` provides constants for each field value and builder functions that
compose them:

```haskell
buildOpcodeAlu :: AluOp -> SrcType -> AluCls -> Opcode
buildOpcodeJmp :: JmpOp -> SrcType -> JmpCls -> Opcode
buildOpcodeLd  :: LdStMode -> LdStSize -> LoadCls  -> Opcode
buildOpcodeSt  :: LdStMode -> LdStSize -> StoreCls -> Opcode
buildOpcodeEnd :: SrcByteOrder -> AluCls -> Opcode  -- for BPF_END
```

All constant values are defined as named `Opcode` (= `Word8`) values so the
composition is readable and self-documenting.

---

## Adding a New Instruction

Follow these steps when adding a new instruction class (e.g. LD/LDX/ST/STX):

### 1. Verify types exist in `Types.hs`

Check that the relevant ADTs are already defined.  For load/store, `LoadCls`,
`StoreCls`, `LdStSize`, and `LdStMode` are all present.  Add any missing types
here — this is the only place types should live.

### 2. Verify opcode constants exist in `Opcode.hs`

Check that the opcode bit constants and the `buildOpcode*` function are already
defined.  For load/store, `buildOpcodeLd` and `buildOpcodeSt` are present.  If
a builder is missing, add it following the same bitwise-OR pattern.

### 3. Add a generic builder to `GenericInstructions.hs`

Generic builders handle the common encoding logic for a family of instructions.
They take high-level types (e.g. `LdStSize`, `Reg`, `Int16`) and produce a
`StandardInstruction`.

Name generic builders with a `make` or `generic` prefix to distinguish them
from the public API.  Keep them unexported if they are implementation details.

### 4. Add public wrapper functions to `Instructions.hs`

Public functions follow the naming convention `bpf_<operation><width>` (e.g.
`bpf_ldx64`, `bpf_stx32`).  They should be thin wrappers over the generic
builders, adding only input validation (e.g. `checkDivZero`).

Include a Haskell doc comment explaining:
- what the instruction does
- which fields carry what data
- any constraints or edge cases

### 5. Update `docs/instruction-set.md`

Add the new instruction(s) to the appropriate table.  Update the "Status"
notes if a class moves from unimplemented to implemented.

---

## Special Offset Field Reuse

The `_off` (offset) field is normally used for jump targets and pointer
arithmetic, but some instructions repurpose it for secondary data:

| Instruction   | `_off` value  | Reason                                          |
|---------------|---------------|-------------------------------------------------|
| SDIV / SMOD   | `1`           | Same opcode bits as DIV/MOD; offset discriminates |
| MOVSX         | `8`, `16`, `32` | Sign-extension width                          |

When adding instructions that reuse fields, document it explicitly in both the
source comments and this table.

---

## Encoding

### Why ByteString.Builder

`Data.ByteString.Builder` provides an efficient way to construct byte sequences.
A `Builder` is a buffer-filling function, not a byte array.  Concatenating two
builders with `<>` appends the *functions*, not the memory — O(1) concat.  The
actual bytes are only materialised when you call `toLazyByteString`, which
produces a lazy linked list of memory chunks ready for writing to a file or
socket.

The key operations used in `Encode.hs`:
- `word8` — encode a `Word8` into a `Builder`
- `int16LE` — encode an `Int16` in little-endian
- `int32LE` — encode an `Int32` in little-endian
- `<>` (from `Semigroup`) — concatenate two builders
- `mconcat` (from `Monoid`) — fold a list of builders into one

These are *encoder instructions*, not the Haskell types `Word8`, `Int16`,
`Int32` — each takes a typed value and returns a `Builder`.

### Binary layout

`Encode.hs` converts an `Instruction` to a `Data.ByteString.Builder`.  The
layout (little-endian) is:

```
word8   opcode
word8   (src_reg << 4) | dst_reg
int16LE offset
int32LE imm
```

For `ExtendedInstruction` (128-bit), two additional `int32LE` words follow:
`reserved` (must be zero) and `next_imm`.  Both constructors are pattern-matched
in `encodeInstruction`, so `StandardInstruction` emits 8 bytes and
`ExtendedInstruction` emits 16 bytes.

---

## RFC 9669 Conformance

The target specification is [RFC 9669](https://www.rfc-editor.org/rfc/rfc9669).
Conformance groups currently implemented:

| Group      | Status      |
|------------|-------------|
| base32     | Complete    |
| base64     | Complete    |
| divmul32   | Complete    |
| divmul64   | Complete    |
| atomic32   | Complete    |
| atomic64   | Complete    |

Load/store memory instructions (LDX, ST, STX — `BPF_MEM` mode, all widths) are
fully implemented.  Atomic operations (`BPF_ATOMIC` mode — ADD, OR, AND, XOR
with optional FETCH, plus XCHG and CMPXCHG) are fully implemented for both
32-bit and 64-bit widths.  Legacy `BPF_ABS` / `BPF_IND` packet-access modes
are not implemented (socket-filter / classic-BPF compat only).

The wide (128-bit) instruction format is fully supported: `ExtendedInstruction`
in `Types.hs`, 16-byte encoding in `Encode.hs`, and `bpf_ld_imm64` as its
only current consumer.
