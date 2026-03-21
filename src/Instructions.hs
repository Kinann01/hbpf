{- HLINT ignore "Use camelCase" -}
module Instructions where

-- Note: function names use the bpf_ prefix with underscores to intentionally
-- mirror the BPF C API naming convention (bpf_map_lookup_elem, bpf_exit, …).

import Data.Int (Int16, Int32, Int64)
import GenericInstructions
import Opcode (getAtomicImm, getAtomicFetchImm)
import Types

-- ---------------------------------------------------------------------------
-- Arithmetic — ADD
-- ---------------------------------------------------------------------------

bpf_add64 :: (SourceType a) => Reg -> a -> Instruction
bpf_add64 = genericAlu64 BPF_ADD

bpf_add32 :: (SourceType a) => Reg -> a -> Instruction
bpf_add32 = genericAlu32 BPF_ADD

-- ---------------------------------------------------------------------------
-- Arithmetic — SUB
-- ---------------------------------------------------------------------------

bpf_sub64 :: (SourceType a) => Reg -> a -> Instruction
bpf_sub64 = genericAlu64 BPF_SUB

bpf_sub32 :: (SourceType a) => Reg -> a -> Instruction
bpf_sub32 = genericAlu32 BPF_SUB

-- ---------------------------------------------------------------------------
-- Arithmetic — MUL
-- ---------------------------------------------------------------------------

bpf_mul64 :: (SourceType a) => Reg -> a -> Instruction
bpf_mul64 = genericAlu64 BPF_MUL

bpf_mul32 :: (SourceType a) => Reg -> a -> Instruction
bpf_mul32 = genericAlu32 BPF_MUL

-- ---------------------------------------------------------------------------
-- Arithmetic — DIV / SDIV  (division by zero guard on immediate sources)
-- ---------------------------------------------------------------------------

bpf_div64 :: (SourceType a) => Reg -> a -> Instruction
bpf_div64 dst src = genericAlu64 BPF_DIV dst $ checkDivZero BPF_DIV src

bpf_div32 :: (SourceType a) => Reg -> a -> Instruction
bpf_div32 dst src = genericAlu32 BPF_DIV dst $ checkDivZero BPF_DIV src

bpf_sdiv64 :: (SourceType a) => Reg -> a -> Instruction
bpf_sdiv64 dst src = genericAlu64 BPF_SDIV dst $ checkDivZero BPF_SDIV src

bpf_sdiv32 :: (SourceType a) => Reg -> a -> Instruction
bpf_sdiv32 dst src = genericAlu32 BPF_SDIV dst $ checkDivZero BPF_SDIV src

-- ---------------------------------------------------------------------------
-- Arithmetic — MOD / SMOD
-- ---------------------------------------------------------------------------

bpf_mod64 :: (SourceType a) => Reg -> a -> Instruction
bpf_mod64 dst src = genericAlu64 BPF_MOD dst $ checkDivZero BPF_MOD src

bpf_mod32 :: (SourceType a) => Reg -> a -> Instruction
bpf_mod32 dst src = genericAlu32 BPF_MOD dst $ checkDivZero BPF_MOD src

bpf_smod64 :: (SourceType a) => Reg -> a -> Instruction
bpf_smod64 dst src = genericAlu64 BPF_SMOD dst $ checkDivZero BPF_SMOD src

bpf_smod32 :: (SourceType a) => Reg -> a -> Instruction
bpf_smod32 dst src = genericAlu32 BPF_SMOD dst $ checkDivZero BPF_SMOD src

-- ---------------------------------------------------------------------------
-- Bitwise — OR / AND / XOR
-- ---------------------------------------------------------------------------

bpf_or64 :: (SourceType a) => Reg -> a -> Instruction
bpf_or64 = genericAlu64 BPF_OR

bpf_or32 :: (SourceType a) => Reg -> a -> Instruction
bpf_or32 = genericAlu32 BPF_OR

bpf_and64 :: (SourceType a) => Reg -> a -> Instruction
bpf_and64 = genericAlu64 BPF_AND

bpf_and32 :: (SourceType a) => Reg -> a -> Instruction
bpf_and32 = genericAlu32 BPF_AND

bpf_xor64 :: (SourceType a) => Reg -> a -> Instruction
bpf_xor64 = genericAlu64 BPF_XOR

bpf_xor32 :: (SourceType a) => Reg -> a -> Instruction
bpf_xor32 = genericAlu32 BPF_XOR

-- ---------------------------------------------------------------------------
-- Shift — LSH / RSH / ARSH
-- ---------------------------------------------------------------------------

bpf_lsh64 :: (SourceType a) => Reg -> a -> Instruction
bpf_lsh64 = genericAlu64 BPF_LSH

bpf_lsh32 :: (SourceType a) => Reg -> a -> Instruction
bpf_lsh32 = genericAlu32 BPF_LSH

bpf_rsh64 :: (SourceType a) => Reg -> a -> Instruction
bpf_rsh64 = genericAlu64 BPF_RSH

bpf_rsh32 :: (SourceType a) => Reg -> a -> Instruction
bpf_rsh32 = genericAlu32 BPF_RSH

bpf_arsh64 :: (SourceType a) => Reg -> a -> Instruction
bpf_arsh64 = genericAlu64 BPF_ARSH

bpf_arsh32 :: (SourceType a) => Reg -> a -> Instruction
bpf_arsh32 = genericAlu32 BPF_ARSH

-- ---------------------------------------------------------------------------
-- Unary — NEG
-- ---------------------------------------------------------------------------

bpf_neg64 :: Reg -> Instruction
bpf_neg64 = neg64

bpf_neg32 :: Reg -> Instruction
bpf_neg32 = neg32

-- ---------------------------------------------------------------------------
-- Move — MOV (register or immediate) / MOVSX (register only, sign-extends)
--
-- bpf_mov{32,64} accept both a register and an integer immediate:
--   bpf_mov64 R1 R2          -- dst = src
--   bpf_mov64 R1 (42 :: Int) -- dst = imm
--
-- bpf_movSX{32,64} are register-only; the extension size controls how many
-- low-order bits of src are sign-extended into dst.
-- ---------------------------------------------------------------------------

bpf_mov64 :: (SourceType a) => Reg -> a -> Instruction
bpf_mov64 = mov64

bpf_mov32 :: (SourceType a) => Reg -> a -> Instruction
bpf_mov32 = mov32

bpf_movSX64 :: Reg -> Reg -> ExtensionSize -> Instruction
bpf_movSX64 = movSX64

bpf_movSX32 :: Reg -> Reg -> ExtensionSize -> Instruction
bpf_movSX32 = movSX32

-- ---------------------------------------------------------------------------
-- Byte-swap — END (BPF_ALU) and BSWAP (BPF_ALU64)
--
-- bpf_tole: convert dst to little-endian   (BPF_ALU | BPF_END | BPF_TO_LE)
-- bpf_toBe: convert dst to big-endian      (BPF_ALU | BPF_END | BPF_TO_BE)
-- bpf_bswap: unconditional byte swap       (BPF_ALU64 | BPF_END | BPF_TO_LE)
--
-- The width argument (Width16 / Width32 / Width64) selects how many low-order
-- bits are byte-swapped; the remaining high bits are zeroed.
-- ---------------------------------------------------------------------------

bpf_tole :: Reg -> EndianWidth -> Instruction
bpf_tole dst width = makeEND dst width LittleEndian

bpf_toBe :: Reg -> EndianWidth -> Instruction
bpf_toBe dst width = makeEND dst width BigEndian

bpf_bswap :: Reg -> EndianWidth -> Instruction
bpf_bswap = makeENDBswap

-- ---------------------------------------------------------------------------
-- Load — 64-bit immediate (wide / extended instruction)
--
-- bpf_ld_imm64 loads a 64-bit constant into dst.  It encodes as two
-- consecutive 64-bit instruction slots (128 bits total) in the output stream.
-- The lower 32 bits of the constant go into the first slot's imm field; the
-- upper 32 bits go into the second slot's imm field (next_imm).
--
-- Usage:
--   bpf_ld_imm64 R1 0xDEADBEEFCAFEBABE
-- ---------------------------------------------------------------------------

bpf_ld_imm64 :: Reg -> Int64 -> Instruction
bpf_ld_imm64 = makeLdImm64

-- ---------------------------------------------------------------------------
-- Jump — unconditional (BPF_JA)
--
-- bpf_ja uses the BPF_JMP class and stores a 32-bit signed offset in _imm,
-- giving a larger jump range than BPF_JMP32.
--
-- bpf_ja32 uses the BPF_JMP32 class and stores a 16-bit signed offset in _off.
-- ---------------------------------------------------------------------------

bpf_ja :: Int32 -> Instruction
bpf_ja = makeJa64

bpf_ja32 :: Int16 -> Instruction
bpf_ja32 = makeJa32

-- ---------------------------------------------------------------------------
-- Jump — conditional, 64-bit comparison (BPF_JMP)
--
-- If the condition holds, pc += off (16-bit signed).
-- Source can be a register or a 32-bit immediate:
--   bpf_jeq64 R0 R1 4            -- jump +4 if R0 == R1
--   bpf_jeq64 R0 (0 :: Int) (-2) -- jump -2 if R0 == 0
-- ---------------------------------------------------------------------------

bpf_jeq64 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jeq64 = genericJmp64 BPF_JEQ

bpf_jne64 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jne64 = genericJmp64 BPF_JNE

bpf_jgt64 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jgt64 = genericJmp64 BPF_JGT

bpf_jge64 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jge64 = genericJmp64 BPF_JGE

bpf_jlt64 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jlt64 = genericJmp64 BPF_JLT

bpf_jle64 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jle64 = genericJmp64 BPF_JLE

bpf_jsgt64 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jsgt64 = genericJmp64 BPF_JSGT

bpf_jsge64 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jsge64 = genericJmp64 BPF_JSGE

bpf_jslt64 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jslt64 = genericJmp64 BPF_JSLT

bpf_jsle64 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jsle64 = genericJmp64 BPF_JSLE

bpf_jset64 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jset64 = genericJmp64 BPF_JSET

-- ---------------------------------------------------------------------------
-- Jump — conditional, 32-bit comparison (BPF_JMP32)
--
-- Same semantics as the 64-bit variants but only the lower 32 bits of dst
-- and src are compared.
-- ---------------------------------------------------------------------------

bpf_jeq32 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jeq32 = genericJmp32 BPF_JEQ

bpf_jne32 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jne32 = genericJmp32 BPF_JNE

bpf_jgt32 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jgt32 = genericJmp32 BPF_JGT

bpf_jge32 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jge32 = genericJmp32 BPF_JGE

bpf_jlt32 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jlt32 = genericJmp32 BPF_JLT

bpf_jle32 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jle32 = genericJmp32 BPF_JLE

bpf_jsgt32 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jsgt32 = genericJmp32 BPF_JSGT

bpf_jsge32 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jsge32 = genericJmp32 BPF_JSGE

bpf_jslt32 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jslt32 = genericJmp32 BPF_JSLT

bpf_jsle32 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jsle32 = genericJmp32 BPF_JSLE

bpf_jset32 :: (SourceType a) => Reg -> a -> Int16 -> Instruction
bpf_jset32 = genericJmp32 BPF_JSET

-- ---------------------------------------------------------------------------
-- Call and Exit
--
-- bpf_call invokes a kernel helper function by its numeric ID.  Arguments are
-- passed in R1–R5; the return value is in R0.  See the kernel's bpf_func_id
-- enum for valid IDs.
--
-- bpf_exit terminates the BPF program and returns R0 to the caller.
-- Every BPF program must end with bpf_exit.
-- ---------------------------------------------------------------------------

bpf_call :: Int32 -> Instruction
bpf_call = makeCall

bpf_exit :: Instruction
bpf_exit = makeExit

-- ---------------------------------------------------------------------------
-- Load — LDX (load from memory into register)
--
-- dst = *(size *)(src + off)
--
-- src holds the base address; off is a signed 16-bit byte offset.
-- The width suffix selects the transfer size: 8, 16, 32, or 64 bits.
-- Narrower loads zero-extend into the 64-bit destination register.
--
-- Usage:
--   bpf_ldx64 R1 R10 (-8)   -- R1 = *(u64 *)(R10 - 8)
--   bpf_ldx32 R0 R1  0      -- R0 = *(u32 *)(R1 + 0), zero-extended
-- ---------------------------------------------------------------------------

bpf_ldx64 :: Reg -> Reg -> Int16 -> Instruction
bpf_ldx64 = makeGenericLdx BPF_DW

bpf_ldx32 :: Reg -> Reg -> Int16 -> Instruction
bpf_ldx32 = makeGenericLdx BPF_W

bpf_ldx16 :: Reg -> Reg -> Int16 -> Instruction
bpf_ldx16 = makeGenericLdx BPF_H

bpf_ldx8 :: Reg -> Reg -> Int16 -> Instruction
bpf_ldx8 = makeGenericLdx BPF_B

-- ---------------------------------------------------------------------------
-- Store — ST (store sign-extended immediate to memory)
--
-- *(size *)(dst + off) = imm
--
-- dst holds the base address; off is a signed 16-bit byte offset.
-- imm is a 32-bit signed immediate, sign-extended to the transfer width.
--
-- Usage:
--   bpf_st32 R10 (-4) 0     -- *(u32 *)(R10 - 4) = 0
--   bpf_st64 R1  8    (-1)  -- *(u64 *)(R1  + 8) = -1 (sign-extended)
-- ---------------------------------------------------------------------------

bpf_st64 :: Reg -> Int16 -> Int32 -> Instruction
bpf_st64 = makeGenericSt BPF_DW

bpf_st32 :: Reg -> Int16 -> Int32 -> Instruction
bpf_st32 = makeGenericSt BPF_W

bpf_st16 :: Reg -> Int16 -> Int32 -> Instruction
bpf_st16 = makeGenericSt BPF_H

bpf_st8 :: Reg -> Int16 -> Int32 -> Instruction
bpf_st8 = makeGenericSt BPF_B

-- ---------------------------------------------------------------------------
-- Store — STX (store register to memory)
--
-- *(size *)(dst + off) = src
--
-- dst holds the base address; src holds the value to store.
-- off is a signed 16-bit byte offset.
-- Only the low-order bits of src are written for sub-64-bit widths.
--
-- Usage:
--   bpf_stx64 R10 R1 (-8)  -- *(u64 *)(R10 - 8) = R1
--   bpf_stx32 R1  R2 4     -- *(u32 *)(R1  + 4) = R2 (low 32 bits)
-- ---------------------------------------------------------------------------

bpf_stx64 :: Reg -> Reg -> Int16 -> Instruction
bpf_stx64 = makeGenericStx BPF_DW

bpf_stx32 :: Reg -> Reg -> Int16 -> Instruction
bpf_stx32 = makeGenericStx BPF_W

bpf_stx16 :: Reg -> Reg -> Int16 -> Instruction
bpf_stx16 = makeGenericStx BPF_H

bpf_stx8 :: Reg -> Reg -> Int16 -> Instruction
bpf_stx8 = makeGenericStx BPF_B

-- ---------------------------------------------------------------------------
-- Atomic — basic (no fetch)
--
-- *(size *)(dst + off) <op>= src
--
-- The original value at the memory location is NOT returned.
-- Only 32-bit (BPF_W) and 64-bit (BPF_DW) widths are valid.
--
-- Usage:
--   bpf_atomic_add64 R10 R1 (-8)  -- *(u64 *)(R10 - 8) += R1
-- ---------------------------------------------------------------------------

bpf_atomic_add64 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_add64 = makeGenericAtomic BPF_DW (getAtomicImm ATOMIC_ADD)

bpf_atomic_add32 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_add32 = makeGenericAtomic BPF_W (getAtomicImm ATOMIC_ADD)

bpf_atomic_or64 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_or64 = makeGenericAtomic BPF_DW (getAtomicImm ATOMIC_OR)

bpf_atomic_or32 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_or32 = makeGenericAtomic BPF_W (getAtomicImm ATOMIC_OR)

bpf_atomic_and64 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_and64 = makeGenericAtomic BPF_DW (getAtomicImm ATOMIC_AND)

bpf_atomic_and32 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_and32 = makeGenericAtomic BPF_W (getAtomicImm ATOMIC_AND)

bpf_atomic_xor64 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_xor64 = makeGenericAtomic BPF_DW (getAtomicImm ATOMIC_XOR)

bpf_atomic_xor32 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_xor32 = makeGenericAtomic BPF_W (getAtomicImm ATOMIC_XOR)

-- ---------------------------------------------------------------------------
-- Atomic — fetch variants
--
-- src = atomic_fetch_<op>(dst + off, src)
--
-- Like the basic variants, but the original value at the memory location is
-- written back to src_reg before the operation is applied.
--
-- Usage:
--   bpf_atomic_fetch_add64 R10 R1 (-8)  -- R1 = old; *(u64 *)(R10 - 8) += R1
-- ---------------------------------------------------------------------------

bpf_atomic_fetch_add64 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_fetch_add64 = makeGenericAtomic BPF_DW (getAtomicFetchImm ATOMIC_ADD)

bpf_atomic_fetch_add32 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_fetch_add32 = makeGenericAtomic BPF_W (getAtomicFetchImm ATOMIC_ADD)

bpf_atomic_fetch_or64 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_fetch_or64 = makeGenericAtomic BPF_DW (getAtomicFetchImm ATOMIC_OR)

bpf_atomic_fetch_or32 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_fetch_or32 = makeGenericAtomic BPF_W (getAtomicFetchImm ATOMIC_OR)

bpf_atomic_fetch_and64 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_fetch_and64 = makeGenericAtomic BPF_DW (getAtomicFetchImm ATOMIC_AND)

bpf_atomic_fetch_and32 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_fetch_and32 = makeGenericAtomic BPF_W (getAtomicFetchImm ATOMIC_AND)

bpf_atomic_fetch_xor64 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_fetch_xor64 = makeGenericAtomic BPF_DW (getAtomicFetchImm ATOMIC_XOR)

bpf_atomic_fetch_xor32 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_fetch_xor32 = makeGenericAtomic BPF_W (getAtomicFetchImm ATOMIC_XOR)

-- ---------------------------------------------------------------------------
-- Atomic — exchange (XCHG)
--
-- src = xchg(dst + off, src)
--
-- Atomically swaps the value at *(dst + off) with src.  The old memory value
-- is written to src_reg.  Always includes the FETCH flag.
--
-- Usage:
--   bpf_atomic_xchg64 R10 R1 (-8)  -- R1 = old; *(u64 *)(R10 - 8) = R1
-- ---------------------------------------------------------------------------

bpf_atomic_xchg64 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_xchg64 = makeGenericAtomic BPF_DW (getAtomicImm ATOMIC_XCHG)

bpf_atomic_xchg32 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_xchg32 = makeGenericAtomic BPF_W (getAtomicImm ATOMIC_XCHG)

-- ---------------------------------------------------------------------------
-- Atomic — compare and exchange (CMPXCHG)
--
-- R0 = cmpxchg(dst + off, R0, src)
--
-- If *(dst + off) == R0, then *(dst + off) = src.
-- In all cases, R0 is set to the original value at *(dst + off).
-- Always includes the FETCH flag.
--
-- Usage:
--   bpf_atomic_cmpxchg64 R10 R1 (-8)
--     -- if *(u64 *)(R10 - 8) == R0 then *(u64 *)(R10 - 8) = R1
--     -- R0 = original value
-- ---------------------------------------------------------------------------

bpf_atomic_cmpxchg64 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_cmpxchg64 = makeGenericAtomic BPF_DW (getAtomicImm ATOMIC_CMPXCHG)

bpf_atomic_cmpxchg32 :: Reg -> Reg -> Int16 -> Instruction
bpf_atomic_cmpxchg32 = makeGenericAtomic BPF_W (getAtomicImm ATOMIC_CMPXCHG)

-- ---------------------------------------------------------------------------
-- Verifiers
-- ---------------------------------------------------------------------------

-- Guard against compile-time division/modulo by zero for immediate operands.
-- For register sources the check cannot be performed statically, so we pass
-- them through unchanged; the kernel verifier handles it at load time.
checkDivZero :: (SourceType a) => AluOp -> a -> a
checkDivZero op src =
  case getSrcBit src of
    BPF_K ->
      if getImmVal src == 0
        then error (show op ++ ": division by zero (immediate source)")
        else src
    BPF_X -> src
