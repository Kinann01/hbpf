# Program.hs — The BPF Program Builder (Layer 2)

## What it is

Program.hs provides a monadic DSL for writing complete eBPF programs. Where Layer 1 (`Instructions.hs`, `Encode.hs`) gives you individual instruction constructors, Program.hs lets you compose them into a full program with symbolic labels and automatic jump offset resolution.

The core type is:

```haskell
type BPF a = State BuildState a
```

A `BPF ()` value is a description of a program. It doesn't *run* anything — it builds up an instruction sequence inside a `State` monad. You turn it into actual instructions by calling `assemble`.

## How it works internally

### BuildState

Every `BPF` action reads and writes a `BuildState`:

```haskell
data BuildState = BuildState
  { _insns   :: !(Seq Instruction)    -- emitted instructions (in order)
  , _nextPC  :: !Int                  -- current PC slot counter
  , _nextLbl :: !Int                  -- fresh label counter
  , _labels  :: !(Map Label Int)      -- label → PC slot it points to
  , _fixups  :: ![Fixup]              -- pending jump patches
  }
```

- **`_insns`**: A `Seq` (not a list) of instructions emitted so far. `Seq` is used because we need efficient append *and* random-access update (for patching jumps later).
- **`_nextPC`**: The current program counter. This is not the same as the number of instructions — wide instructions (`ldImm64`) occupy 2 PC slots while being a single `Instruction` value. This distinction is critical for correct jump offset calculation.
- **`_nextLbl`**: A counter for generating unique `Label` values.
- **`_labels`**: Maps each placed label to its PC position.
- **`_fixups`**: A list of deferred patches — jump instructions that reference labels whose positions may not be known at emit time.

### emit and emitIndexed

Every instruction wrapper in Program.hs ultimately calls one of these:

```haskell
emit :: Instruction -> BPF ()
```

Appends an instruction to `_insns` and advances `_nextPC` by the instruction's slot count (1 for standard, 2 for wide).

```haskell
emitIndexed :: Instruction -> BPF (Int, Int)
```

Same as `emit`, but also returns the `Seq` index and the PC slot of the emitted instruction. This is used by jump wrappers so they know *where* to patch later.

### Labels

Labels are symbolic names for positions in the instruction stream. They exist because when you write a forward jump, the target instruction hasn't been emitted yet — you don't know the offset.

```haskell
newtype Label = Label Int
```

Two operations:

- **`newLabel`** — allocates a fresh label. Does *not* define where it points. Think of it as declaring a variable.
- **`label lbl`** — records that `lbl` points to the *current* `_nextPC`. Think of it as assigning to that variable. Any jump to `lbl` will land on whatever instruction is emitted next.

You can place a label before or after the jumps that reference it. Forward jumps (jumping ahead to code not yet emitted) and backward jumps (looping back) both work.

### The fixup system

When you write `jeq64 R1 R2 myLabel`, Program.hs doesn't know the offset yet. So it:

1. Emits the jump instruction with **offset 0** as a placeholder.
2. Records a `Fixup` noting: "the instruction at Seq index N, at PC slot P, needs its offset field patched to point to `myLabel`."

```haskell
data Fixup = Fixup
  { _fxSeqIdx :: !Int       -- index into the Seq (for Seq.update)
  , _fxPCSlot :: !Int       -- PC of the jump instruction
  , _fxLabel  :: !Label     -- target label
  , _fxKind   :: !FixupKind -- which field to patch: _off or _imm
  }
```

**FixupKind** matters because eBPF has two kinds of jump encoding:

- **`FixupOff`** — conditional jumps and `ja32` store the offset in the 16-bit `_off` field (`Int16` range).
- **`FixupImm`** — `ja` (the 64-bit-class unconditional jump) stores the offset in the 32-bit `_imm` field (`Int32` range).

### assemble

```haskell
assemble :: BPF () -> Either String [Instruction]
```

This is the entry point. It:

1. Runs the `BPF ()` computation from `initialState`, producing a final `BuildState`.
2. Calls `resolve` to walk every fixup and patch in the real offset.
3. Returns `Right [Instruction]` on success, or `Left errorMsg` if:
   - A label was referenced but never placed (undefined label).
   - A jump offset overflows `Int16` (for conditional jumps) or `Int32` (for `ja`).

**Offset calculation**: For a jump at PC slot `P` targeting a label at PC slot `T`:

```
offset = T - (P + 1)
```

The `+1` is because eBPF jump offsets are relative to the *next* instruction after the jump, not the jump itself. This matches the kernel's semantics.

### PC slots vs Seq indices

This is the most subtle part of the implementation. There are two different "positions" for an instruction:

- **Seq index**: Its position in the `Seq Instruction`. Used for `Seq.update` when patching.
- **PC slot**: Its position as the eBPF VM sees it. A wide instruction (128-bit `ldImm64`) takes 2 slots.

Example:

```
Seq index 0: ldImm64 R1 42    → PC slots 0-1
Seq index 1: add64 R0 R1      → PC slot 2
Seq index 2: exit             → PC slot 3
```

Jump offsets are calculated in **PC slots** (because that's what the kernel uses), but patching happens via **Seq index** (because that's how we access the instruction in the sequence). The fixup records both.

## The API

Every exported function in Program.hs is a thin wrapper that calls `emit` with the corresponding Layer 1 instruction constructor. For example:

```haskell
add64 :: (SourceType a) => Reg -> a -> BPF ()
add64 dst src = emit $ I.bpf_add64 dst src
```

The full API mirrors the eBPF instruction set:

### Arithmetic (ALU)

All arithmetic ops come in 64-bit and 32-bit variants and accept either a register or an immediate as the source (via the `SourceType` typeclass).

| 64-bit | 32-bit | Operation |
|--------|--------|-----------|
| `add64` | `add32` | Addition |
| `sub64` | `sub32` | Subtraction |
| `mul64` | `mul32` | Multiplication |
| `div64` | `div32` | Unsigned division |
| `sdiv64` | `sdiv32` | Signed division |
| `mod64` | `mod32` | Unsigned modulo |
| `smod64` | `smod32` | Signed modulo |
| `or64` | `or32` | Bitwise OR |
| `and64` | `and32` | Bitwise AND |
| `xor64` | `xor32` | Bitwise XOR |
| `lsh64` | `lsh32` | Left shift |
| `rsh64` | `rsh32` | Unsigned right shift |
| `arsh64` | `arsh32` | Arithmetic (signed) right shift |
| `neg64` | `neg32` | Negation (unary, no source operand) |

### Move

- **`mov64 dst src`** / **`mov32 dst src`** — move register or immediate into `dst`.
- **`movSX64 dst src size`** / **`movSX32 dst src size`** — move with sign extension. `size` is `Ext8`, `Ext16`, or `Ext32`, specifying how many bits of `src` to sign-extend.

### Byte swap

- **`tole dst width`** — convert to little-endian.
- **`toBe dst width`** — convert to big-endian.
- **`bswap dst width`** — unconditional byte swap.

`width` is `Width16`, `Width32`, or `Width64`.

### Load / Store

**Load from memory** (register + offset → register):

- `ldx64 dst src off` — load 8 bytes from `[src + off]` into `dst`
- `ldx32`, `ldx16`, `ldx8` — load 4, 2, 1 bytes (zero-extended)

**Store immediate to memory**:

- `st64 dst off imm` — store 8-byte immediate to `[dst + off]`
- `st32`, `st16`, `st8` — store 4, 2, 1 byte immediate

**Store register to memory**:

- `stx64 dst src off` — store `src` (8 bytes) to `[dst + off]`
- `stx32`, `stx16`, `stx8` — store 4, 2, 1 bytes

**Wide immediate load**:

- `ldImm64 dst val` — load a full 64-bit constant into `dst`. This is a 128-bit (extended) instruction that occupies **2 PC slots**. It's the only way to load a value larger than 32 bits.

### Atomic

All atomic operations take `dst src off` where the memory location is `[dst + off]` and `src` provides the operand.

**Basic** (no return): `atomicAdd64/32`, `atomicOr64/32`, `atomicAnd64/32`, `atomicXor64/32`

**Fetch** (old value returned in `src`): `atomicFetchAdd64/32`, `atomicFetchOr64/32`, `atomicFetchAnd64/32`, `atomicFetchXor64/32`

**Exchange**: `atomicXchg64/32` — swap `src` with value at `[dst + off]`, old value returned in `src`.

**Compare-and-swap**: `atomicCmpxchg64/32` — if `[dst + off] == R0`, then `[dst + off] = src`. Old value returned in `R0`.

### Jumps

All conditional jumps take the form: `jXX dst src label`

The source can be a register or immediate. The label is a symbolic `Label` created with `newLabel`.

**Unsigned comparisons**: `jeq`, `jne`, `jgt`, `jge`, `jlt`, `jle`
**Signed comparisons**: `jsgt`, `jsge`, `jslt`, `jsle`
**Bitwise test**: `jset` (jumps if `dst & src != 0`)

Each has a 64-bit and 32-bit variant (e.g. `jeq64`, `jeq32`). The 32-bit variants compare only the lower 32 bits of the registers.

**Unconditional jumps**:

- `ja label` — uses the `_imm` field (32-bit offset range, BPF_JMP class).
- `ja32 label` — uses the `_off` field (16-bit offset range, BPF_JMP32 class).

### Control flow

- **`exit`** — terminates the program. The return value must be in `R0`.
- **`call helperID`** — calls a kernel helper function. Arguments go in `R1`–`R5`, return value lands in `R0`. Registers `R1`–`R5` are **clobbered** after the call. `R6`–`R9` are callee-saved.

## Writing a program: end to end

### Minimal example

```haskell
import Program
import Types

-- A program that returns 0.
myProg :: BPF ()
myProg = do
  mov64 R0 (0 :: Int)
  exit
```

To get the instruction list:

```haskell
case assemble myProg of
  Left err -> error err
  Right instructions -> -- [StandardInstruction ..., StandardInstruction ...]
```

To get raw bytes, pipe through `Encode.encodeProgram`:

```haskell
import Encode (encodeProgram)
import Data.ByteString.Builder (toLazyByteString)

case assemble myProg of
  Right is -> toLazyByteString (encodeProgram is)
```

### Forward jump

```haskell
myProg :: BPF ()
myProg = do
  end <- newLabel              -- declare label (position unknown)
  mov64 R0 (0 :: Int)         -- PC 0
  jeq64 R1 (0 :: Int) end     -- PC 1: if R1 == 0, jump to end
  mov64 R0 (1 :: Int)         -- PC 2: only reached if R1 != 0
  label end                    -- place label at PC 3
  exit                         -- PC 3
```

At assemble time, the `jeq64` at PC 1 gets offset `3 - (1+1) = 1`.

### Backward jump (loop)

```haskell
myProg :: BPF ()
myProg = do
  top <- newLabel
  label top                    -- PC 0
  add64 R0 (1 :: Int)         -- PC 0
  jlt64 R0 (10 :: Int) top    -- PC 1: if R0 < 10, jump back to top
  exit                         -- PC 2
```

The `jlt64` at PC 1 gets offset `0 - (1+1) = -2`.

### Multiple labels (if/else)

```haskell
myProg :: BPF ()
myProg = do
  zero <- newLabel
  done <- newLabel
  jeq64 R0 (0 :: Int) zero    -- PC 0: if R0 == 0, goto zero
  mov64 R0 (1 :: Int)         -- PC 1: else branch
  ja done                      -- PC 2: skip over the zero branch
  label zero                   -- PC 3
  mov64 R0 (0 :: Int)         -- PC 3: zero branch
  label done                   -- PC 4
  exit                         -- PC 4
```

### Wide instructions and PC counting

```haskell
myProg :: BPF ()
myProg = do
  end <- newLabel
  ldImm64 R1 42               -- PC 0 (occupies slots 0 and 1)
  ja end                       -- PC 2
  mov64 R0 (0 :: Int)         -- PC 3
  label end                    -- PC 4
  exit                         -- PC 4
```

The `ja` at PC 2 gets offset `4 - (2+1) = 1`. Even though there's only one instruction between the jump and the label (`mov64`), the math works because offsets are in PC slots, not instruction count. The `ldImm64` consumed 2 slots, which is why the `ja` is at PC 2, not PC 1.

### Calling helpers

```haskell
import Helpers (helper_get_current_pid_tgid_id)

myProg :: BPF ()
myProg = do
  call helper_get_current_pid_tgid_id  -- result in R0
  mov64 R6 R0                          -- save to callee-saved register
  -- ... R1-R5 are now clobbered ...
  mov64 R0 R6
  exit
```

Note: `call` takes an `Int32` helper ID directly. The `Helpers` module exports both the `Instruction` values (for Layer 1) and the `_id` constants. At Layer 2, use the `_id` constants with `call`.

## Error cases

`assemble` returns `Left` in two cases:

1. **Undefined label** — a label was referenced in a jump but `label` was never called for it.
2. **Offset overflow** — the distance between a jump and its target exceeds `Int16` range (for conditional jumps / `ja32`) or `Int32` range (for `ja`). In practice, `Int16` overflow is the one you might hit — it limits conditional jumps to ±32767 instructions.

## Relationship to Layer 1

Program.hs *wraps* Layer 1 — it does not replace it. Every `BPF ()` action produces the same `Instruction` values that `Instructions.hs` builds directly. The difference is:

- **Layer 1**: You build a `[Instruction]` by hand and calculate jump offsets yourself.
- **Layer 2**: You write monadic code with symbolic labels and `assemble` calculates the offsets for you.

The output of `assemble` is a `[Instruction]` — exactly the same type Layer 1 produces. You can mix both: use `emit` to inject any raw `Instruction` into a `BPF` program.

## What Program.hs does NOT do

- **Register allocation** — you manage registers manually. You need to know that R1–R5 are arguments/clobbered, R6–R9 are callee-saved, R10 is the frame pointer (read-only), and R0 is the return value.
- **Stack management** — there's no `stackAlloc`. To use the stack, you work with R10 and negative offsets directly (e.g. `stx64 R10 R1 (-8)` to store R1 at the top of the stack).
- **Type-level program type restrictions** — any helper can be called from any program. The kernel verifier will reject invalid combinations at load time.