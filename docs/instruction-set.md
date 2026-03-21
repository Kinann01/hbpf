# eBPF Instruction Set

## Notes

- Reference: [RFC 9669](https://www.rfc-editor.org/rfc/rfc9669)
- Conformance groups implemented: base32, base64, divmul32, divmul64, atomic32, atomic64
- All multi-byte fields are little-endian (LE)

---

## Instruction Format

### Standard (64-bit)

Every standard eBPF instruction is exactly 64 bits wide:

```
MSB                                                           LSB
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    opcode     |     regs      |            offset             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              imm                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Fields (from least-significant byte):

| Field    | Width | Type            | Description                                      |
|----------|-------|-----------------|--------------------------------------------------|
| `opcode` | 8 bit | Word8           | Instruction class, source bit, and operation     |
| `regs`   | 8 bit | Word8           | src_reg (high 4 bits) \| dst_reg (low 4 bits)    |
| `offset` | 16 bit| Int16 (signed)  | Jump target offset or pointer arithmetic offset  |
| `imm`    | 32 bit| Int32 (signed)  | Immediate constant value                         |

### Wide (128-bit)

Some instructions need a 64-bit immediate (e.g. loading a 64-bit constant or a
map file descriptor).  A second 64-bit word is appended immediately after the
standard encoding:

```
MSB                                                           LSB
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    opcode     |     regs      |            offset             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              imm                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           reserved                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           next_imm                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

> **Status:** Fully implemented. `ExtendedInstruction` in `Types.hs` holds both
> halves; `Encode.hs` emits 16 bytes for it; `bpf_ld_imm64` builds one.

---

## Opcode Structure

### ALU, ALU64, JMP, JMP32

```
  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
|    operation  | src |  class  |
+---+---+---+---+---+---+---+---+
```

| Bits  | Width | Name        | Description                                      |
|-------|-------|-------------|--------------------------------------------------|
| [7:4] | 4 bit | operation   | Which ALU/JMP operation to perform               |
| [3]   | 1 bit | source (src)| 0 = immediate operand (BPF_K), 1 = register (BPF_X) |
| [2:0] | 3 bit | class       | Instruction class (ALU=0x4, ALU64=0x7, JMP=0x5, JMP32=0x6) |

### LD, LDX, ST, STX

```
  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
|    mode   |  size |  class    |
+---+---+---+---+---+---+---+---+
```

| Bits  | Width | Name  | Description                                               |
|-------|-------|-------|-----------------------------------------------------------|
| [7:5] | 3 bit | mode  | Addressing mode (IMM, ABS, IND, MEM, ATOMIC)             |
| [4:3] | 2 bit | size  | Operand size (W=32, H=16, B=8, DW=64)                    |
| [2:0] | 3 bit | class | Instruction class (LD=0x0, LDX=0x1, ST=0x2, STX=0x3)    |

---

## Registers

The `regs` byte packs two 4-bit register numbers:

```
+-+-+-+-+-+-+-+-+
|src_reg|dst_reg|
+-+-+-+-+-+-+-+-+
```

- `dst_reg` (bits [3:0]): destination register, R0–R10
- `src_reg` (bits [7:4]): source register, R0–R10, or 0 when the source is an immediate

eBPF has eleven 64-bit registers (R0–R10).  R10 is read-only (frame pointer).

| Register | Role                                        |
|----------|---------------------------------------------|
| R0       | Return value of helper calls and BPF program |
| R1–R5    | Arguments to helper function calls           |
| R6–R9    | Callee-saved (preserved across helper calls) |
| R10      | Read-only frame pointer                      |

---

## Instruction Classes and Operations

### ALU (BPF_ALU / BPF_ALU64)

| Operation | Opcode bits [7:4] | Haskell API (32-bit / 64-bit)                        |
|-----------|-------------------|------------------------------------------------------|
| ADD       | 0x0               | `bpf_add32`, `bpf_add64`                             |
| SUB       | 0x1               | `bpf_sub32`, `bpf_sub64`                             |
| MUL       | 0x2               | `bpf_mul32`, `bpf_mul64`                             |
| DIV       | 0x3 (off=0)       | `bpf_div32`, `bpf_div64`                             |
| SDIV      | 0x3 (off=1)       | `bpf_sdiv32`, `bpf_sdiv64`                           |
| OR        | 0x4               | `bpf_or32`, `bpf_or64`                               |
| AND       | 0x5               | `bpf_and32`, `bpf_and64`                             |
| LSH       | 0x6               | `bpf_lsh32`, `bpf_lsh64`                             |
| RSH       | 0x7               | `bpf_rsh32`, `bpf_rsh64`                             |
| NEG       | 0x8               | `bpf_neg32`, `bpf_neg64` (unary, no src)             |
| MOD       | 0x9 (off=0)       | `bpf_mod32`, `bpf_mod64`                             |
| SMOD      | 0x9 (off=1)       | `bpf_smod32`, `bpf_smod64`                           |
| XOR       | 0xA               | `bpf_xor32`, `bpf_xor64`                             |
| MOV       | 0xB (off=0)       | `bpf_mov32`, `bpf_mov64`                             |
| MOVSX     | 0xB (off=8/16/32) | `bpf_movSX32`, `bpf_movSX64` (reg-only, sign-extend) |
| ARSH      | 0xC               | `bpf_arsh32`, `bpf_arsh64`                           |
| END       | 0xD               | `bpf_tole`, `bpf_toBe`, `bpf_bswap`                  |

**Notes on SDIV/SMOD:** DIV and SDIV share opcode bits `0x3`; the `offset`
field discriminates them (0 = unsigned, 1 = signed).  Same for MOD/SMOD
(`0x9`).

**Notes on END (byte-swap):**
- `bpf_tole dst w` — convert `dst` to little-endian (`BPF_ALU | BPF_END`, src bit = 0)
- `bpf_toBe dst w` — convert `dst` to big-endian   (`BPF_ALU | BPF_END`, src bit = 1)
- `bpf_bswap dst w` — unconditional byte swap       (`BPF_ALU64 | BPF_END`, src bit = 0)
- Width `w` is `Width16`, `Width32`, or `Width64`; stored in the `imm` field as 16/32/64.

### JMP (BPF_JMP / BPF_JMP32)

Conditional jumps: if `dst <op> src/imm`, then `pc += off`.

| Operation | Opcode bits [7:4] | Haskell API (64-bit / 32-bit comparison)                |
|-----------|-------------------|---------------------------------------------------------|
| JA        | 0x0               | `bpf_ja` (imm, BPF_JMP), `bpf_ja32` (off, BPF_JMP32)  |
| JEQ       | 0x1               | `bpf_jeq64`, `bpf_jeq32`                               |
| JGT       | 0x2               | `bpf_jgt64`, `bpf_jgt32`                               |
| JGE       | 0x3               | `bpf_jge64`, `bpf_jge32`                               |
| JSET      | 0x4               | `bpf_jset64`, `bpf_jset32`                             |
| JNE       | 0x5               | `bpf_jne64`, `bpf_jne32`                               |
| JSGT      | 0x6               | `bpf_jsgt64`, `bpf_jsgt32`                             |
| JSGE      | 0x7               | `bpf_jsge64`, `bpf_jsge32`                             |
| CALL      | 0x8               | `bpf_call helperID`                                    |
| EXIT      | 0x9               | `bpf_exit`                                             |
| JLT       | 0xA               | `bpf_jlt64`, `bpf_jlt32`                               |
| JLE       | 0xB               | `bpf_jle64`, `bpf_jle32`                               |
| JSLT      | 0xC               | `bpf_jslt64`, `bpf_jslt32`                             |
| JSLE      | 0xD               | `bpf_jsle64`, `bpf_jsle32`                             |

**Notes on JA:**
- `bpf_ja off32` uses `BPF_JMP` and stores the signed offset in `_imm` (32 bits),
  giving a ±2 billion instruction range.
- `bpf_ja32 off16` uses `BPF_JMP32` and stores the signed offset in `_off` (16 bits).

**Notes on CALL:**
- `bpf_call helperID` emits `BPF_JMP | BPF_CALL` with `_imm = helperID`.
- Arguments are placed in R1–R5 before the call; the return value arrives in R0.

**Notes on EXIT:**
- Every BPF program must terminate with `bpf_exit`.
- The return value to the kernel is whatever is in R0 at that point.

### LD / LDX / ST / STX

> **Status:** Fully implemented.  `bpf_ld_imm64` (wide load), `bpf_ldx{8,16,32,64}`,
> `bpf_st{8,16,32,64}`, and `bpf_stx{8,16,32,64}` are all available.
> Legacy `BPF_ABS` / `BPF_IND` packet-access modes are not implemented
> (socket-filter / classic-BPF compat only; not needed for modern eBPF).
> Atomic memory operations (`BPF_ATOMIC` mode) are tracked separately.

#### Memory load — LDX

```
dst = *(size *)(src + off)
```

`src` is the base-address register; `off` is a signed 16-bit byte offset.
Narrower loads zero-extend into the 64-bit destination register.

| Width | Haskell API         | Transfer size |
|-------|---------------------|---------------|
| 64    | `bpf_ldx64 dst src off` | 8 bytes   |
| 32    | `bpf_ldx32 dst src off` | 4 bytes   |
| 16    | `bpf_ldx16 dst src off` | 2 bytes   |
| 8     | `bpf_ldx8  dst src off` | 1 byte    |

#### Memory store (immediate) — ST

```
*(size *)(dst + off) = imm
```

`dst` is the base-address register; `imm` is a 32-bit signed immediate.

| Width | Haskell API              | Transfer size |
|-------|--------------------------|---------------|
| 64    | `bpf_st64 dst off imm`   | 8 bytes       |
| 32    | `bpf_st32 dst off imm`   | 4 bytes       |
| 16    | `bpf_st16 dst off imm`   | 2 bytes       |
| 8     | `bpf_st8  dst off imm`   | 1 byte        |

#### Memory store (register) — STX

```
*(size *)(dst + off) = src
```

`dst` is the base-address register; `src` holds the value to store.

| Width | Haskell API              | Transfer size |
|-------|--------------------------|---------------|
| 64    | `bpf_stx64 dst src off`  | 8 bytes       |
| 32    | `bpf_stx32 dst src off`  | 4 bytes       |
| 16    | `bpf_stx16 dst src off`  | 2 bytes       |
| 8     | `bpf_stx8  dst src off`  | 1 byte        |

#### `bpf_ld_imm64` — 64-bit immediate load

```
BPF_LD | BPF_DW | BPF_IMM   opcode = 0x18
```

Loads a 64-bit signed constant into `dst`.  Because the immediate field in a
standard instruction is only 32 bits, this requires the wide (128-bit) format:

| Slot   | opcode | regs      | off | imm            |
|--------|--------|-----------|-----|----------------|
| slot 0 | 0x18   | 0 \| dst  | 0   | lower 32 bits  |
| slot 1 | 0x00   | 0 \| 0    | 0   | upper 32 bits  |

```haskell
bpf_ld_imm64 :: Reg -> Int64 -> Instruction
bpf_ld_imm64 R1 0x00000001FFFFFFFF  -- R1 = 0x00000001FFFFFFFF
```

This produces a single `ExtendedInstruction` value that the encoder turns into
16 bytes.  When placed in a `[Instruction]` program list, the surrounding
instructions remain unaffected.

---

### Atomic (BPF_ATOMIC)

> **Status:** Fully implemented.  All atomic operations with 32-bit and 64-bit
> widths: basic (no fetch), fetch variants, XCHG, and CMPXCHG.

Atomic instructions use the `BPF_STX` class with `BPF_ATOMIC` mode.  The `imm`
field encodes the atomic operation and optional FETCH flag.  Only `BPF_W`
(32-bit) and `BPF_DW` (64-bit) widths are valid.

```
opcode = BPF_ATOMIC | size | BPF_STX
```

#### Basic atomic operations (no fetch)

```
*(size *)(dst + off) <op>= src
```

| Operation | imm    | Haskell API (64-bit / 32-bit)                    |
|-----------|--------|--------------------------------------------------|
| ADD       | `0x00` | `bpf_atomic_add64`, `bpf_atomic_add32`           |
| OR        | `0x40` | `bpf_atomic_or64`, `bpf_atomic_or32`             |
| AND       | `0x50` | `bpf_atomic_and64`, `bpf_atomic_and32`           |
| XOR       | `0xA0` | `bpf_atomic_xor64`, `bpf_atomic_xor32`           |

#### Fetch variants (old value returned in src_reg)

```
src = atomic_fetch_<op>(dst + off, src)
```

| Operation   | imm    | Haskell API (64-bit / 32-bit)                          |
|-------------|--------|--------------------------------------------------------|
| FETCH_ADD   | `0x01` | `bpf_atomic_fetch_add64`, `bpf_atomic_fetch_add32`    |
| FETCH_OR    | `0x41` | `bpf_atomic_fetch_or64`, `bpf_atomic_fetch_or32`      |
| FETCH_AND   | `0x51` | `bpf_atomic_fetch_and64`, `bpf_atomic_fetch_and32`    |
| FETCH_XOR   | `0xA1` | `bpf_atomic_fetch_xor64`, `bpf_atomic_fetch_xor32`    |

#### Exchange and compare-and-exchange (always fetch)

| Operation | imm    | Haskell API (64-bit / 32-bit)                          | Semantics                                                    |
|-----------|--------|--------------------------------------------------------|--------------------------------------------------------------|
| XCHG      | `0xE1` | `bpf_atomic_xchg64`, `bpf_atomic_xchg32`              | `src = xchg(dst + off, src)`                                |
| CMPXCHG   | `0xF1` | `bpf_atomic_cmpxchg64`, `bpf_atomic_cmpxchg32`        | `if *(dst+off)==R0 then *(dst+off)=src; R0 = original value` |

---

## Special Field Reuse

Some instructions repurpose `offset` or `src_reg` for secondary information
rather than pointer arithmetic:

| Instruction          | `offset` reuse                                | `imm` reuse                         |
|----------------------|-----------------------------------------------|-------------------------------------|
| SDIV, SMOD           | `1` to distinguish from unsigned DIV/MOD      | —                                   |
| MOVSX                | Sign-extension width: 8, 16, or 32            | —                                   |
| BPF_END (ALU)        | —                                             | Byte-swap width: 16, 32, or 64      |
| BPF_END (ALU64/bswap)| —                                             | Byte-swap width: 16, 32, or 64      |
| BPF_JA (JMP class)   | —                                             | 32-bit signed jump offset           |
| BPF_CALL             | —                                             | Helper function ID                  |
| BPF_ATOMIC           | —                                             | Atomic operation code + FETCH flag   |
