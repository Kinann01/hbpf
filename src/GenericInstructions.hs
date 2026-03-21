module GenericInstructions where

import Data.Bits ((.&.), shiftR)
import Data.Int (Int16, Int32, Int64)
import Opcode
import Types

-- ---------------------------------------------------------------------------
-- Shared defaults
-- ---------------------------------------------------------------------------

defaultOffsetZero :: Int16
defaultOffsetZero = 0

defaultImmValue :: Int32
defaultImmValue = 0

-- ---------------------------------------------------------------------------
-- SourceType typeclass
--
-- Abstracts over whether an instruction operand is a register (BPF_X) or a
-- 32-bit immediate (BPF_K).  Instantiated for Reg and Int so that a single
-- function like `bpf_add64` works for both:
--
--   bpf_add64 R0 R1          -- register source
--   bpf_add64 R0 (23 :: Int) -- immediate source
-- ---------------------------------------------------------------------------

class SourceType t where
  getSrcBit :: t -> SrcType  -- BPF_X (register) or BPF_K (immediate)
  getSrcReg :: t -> Reg      -- source register, or R0 when immediate
  getImmVal :: t -> Int32    -- immediate value, or 0 when register

instance SourceType Reg where
  getSrcBit _ = BPF_X
  getSrcReg r = r
  getImmVal _ = 0

instance SourceType Int where
  getSrcBit _ = BPF_K
  getSrcReg _ = R0
  getImmVal   = fromIntegral

-- ---------------------------------------------------------------------------
-- ALU generic builders
-- ---------------------------------------------------------------------------

genericAlu32 :: (SourceType t) => AluOp -> Reg -> t -> Instruction
genericAlu32 = makeGenericAlu BPF_ALU

genericAlu64 :: (SourceType t) => AluOp -> Reg -> t -> Instruction
genericAlu64 = makeGenericAlu BPF_ALU64

makeGenericAlu :: (SourceType t) => AluCls -> AluOp -> Reg -> t -> Instruction
makeGenericAlu cls op dst src =
  makeRaw
    (buildOpcodeAlu op (getSrcBit src) cls)
    dst
    (getSrcReg src)
    (getOffLogicAlu op)
    (getImmVal src)

-- Core instruction constructor — takes an already-composed opcode byte.
makeRaw :: Opcode -> Reg -> Reg -> Int16 -> Int32 -> Instruction
makeRaw opcode dst srcReg off imm =
  StandardInstruction
    { _opcode = opcode,
      _dst    = dst,
      _src    = srcReg,
      _off    = off,
      _imm    = imm
    }

-- The offset field is repurposed for signed variants: SDIV and SMOD set it to
-- 1 to distinguish them from their unsigned counterparts at the same opcode.
getOffLogicAlu :: AluOp -> Int16
getOffLogicAlu op = case op of
  BPF_SDIV -> 1
  BPF_SMOD -> 1
  _        -> defaultOffsetZero

-- ---------------------------------------------------------------------------
-- MOV builders
--
-- BPF_MOV accepts both register and immediate sources (unlike BPF_MOVSX which
-- is register-only because its offset field encodes the sign-extension size).
-- ---------------------------------------------------------------------------

makeMovGeneric :: (SourceType t) => AluCls -> Reg -> t -> Instruction
makeMovGeneric cls dst src =
  makeRaw
    (buildOpcodeAlu BPF_MOV (getSrcBit src) cls)
    dst
    (getSrcReg src)
    defaultOffsetZero
    (getImmVal src)

mov32 :: (SourceType t) => Reg -> t -> Instruction
mov32 = makeMovGeneric BPF_ALU

mov64 :: (SourceType t) => Reg -> t -> Instruction
mov64 = makeMovGeneric BPF_ALU64

-- MOVSX is register-only: the offset field carries the sign-extension width.
makeMovSX :: AluCls -> Reg -> Reg -> ExtensionSize -> Instruction
makeMovSX cls dst src size =
  makeRaw
    (buildOpcodeAlu BPF_MOVSX BPF_X cls)
    dst
    src
    (getExtSizeOff size)
    defaultImmValue

movSX32 :: Reg -> Reg -> ExtensionSize -> Instruction
movSX32 = makeMovSX BPF_ALU

movSX64 :: Reg -> Reg -> ExtensionSize -> Instruction
movSX64 = makeMovSX BPF_ALU64

-- Offset encoding for sign-extension sizes used by MOVSX.
getExtSizeOff :: ExtensionSize -> Int16
getExtSizeOff s = case s of
  Ext0  -> 0
  Ext8  -> 8
  Ext16 -> 16
  Ext32 -> 32

-- ---------------------------------------------------------------------------
-- NEG builder  (unary — no source operand)
-- ---------------------------------------------------------------------------

makeNeg :: AluCls -> Reg -> Instruction
makeNeg cls dst =
  makeRaw
    (buildOpcodeAlu BPF_NEG BPF_K cls)
    dst
    R0
    defaultOffsetZero
    defaultImmValue

neg32 :: Reg -> Instruction
neg32 = makeNeg BPF_ALU

neg64 :: Reg -> Instruction
neg64 = makeNeg BPF_ALU64

-- ---------------------------------------------------------------------------
-- END (byte-swap) builders
--
-- Three variants (RFC 9669 §5.3):
--   BPF_ALU  | BPF_END | BPF_TO_LE  -> dst = htole<width>(dst)
--   BPF_ALU  | BPF_END | BPF_TO_BE  -> dst = htobe<width>(dst)
--   BPF_ALU64 | BPF_END | BPF_TO_LE -> dst = bswap<width>(dst)  (unconditional)
--
-- The target byte order is encoded in bit 3 of the opcode (the src-type bit).
-- The imm field carries the operand width: 16, 32, or 64.
-- The src register field is unused and must be zero (R0).
-- ---------------------------------------------------------------------------

getEndianWidth :: EndianWidth -> Int32
getEndianWidth width = case width of
  Width16 -> 16
  Width32 -> 32
  Width64 -> 64

-- to-LE / to-BE: BPF_ALU class, byte order from SrcByteOrder.
makeEND :: Reg -> EndianWidth -> SrcByteOrder -> Instruction
makeEND dst width bo =
  StandardInstruction
    { _opcode = buildOpcodeEnd bo BPF_ALU,
      _dst    = dst,
      _src    = R0,
      _off    = 0,
      _imm    = getEndianWidth width
    }

-- bswap: BPF_ALU64 class, src bit must be 0 (LittleEndian).
makeENDBswap :: Reg -> EndianWidth -> Instruction
makeENDBswap dst width =
  StandardInstruction
    { _opcode = buildOpcodeEnd LittleEndian BPF_ALU64,
      _dst    = dst,
      _src    = R0,
      _off    = 0,
      _imm    = getEndianWidth width
    }

-- ---------------------------------------------------------------------------
-- 64-bit immediate load  (wide / extended instruction)
--
-- BPF_LD | BPF_DW | BPF_IMM loads a 64-bit constant into dst.  It occupies
-- two consecutive 64-bit slots in the instruction stream (128 bits total):
--
--   slot 0: opcode | dst | src=0 | off=0 | imm = lower 32 bits
--   slot 1: opcode=0 | regs=0 | off=0   | imm = upper 32 bits  (next_imm)
--
-- In this library the two slots are represented as a single ExtendedInstruction
-- that the encoder turns into 16 bytes.
-- ---------------------------------------------------------------------------

makeLdImm64 :: Reg -> Int64 -> Instruction
makeLdImm64 dst imm64 =
  ExtendedInstruction
    { _opcode   = buildOpcodeLd BPF_IMM BPF_DW BPF_LD,
      _dst      = dst,
      _src      = R0,
      _off      = 0,
      _imm      = fromIntegral (imm64 .&. 0xFFFFFFFF),
      _res      = 0,
      _imm_next = fromIntegral (imm64 `shiftR` 32)
    }

-- ---------------------------------------------------------------------------
-- Jump generic builders
--
-- Conditional jumps (JEQ, JNE, JGT, …):
--   if dst <op> src/imm: pc += off
--
-- The offset is always a signed 16-bit value stored in the _off field.
-- The source can be a register (BPF_X) or a 32-bit immediate (BPF_K).
-- Both BPF_JMP (64-bit comparison) and BPF_JMP32 (32-bit comparison) share
-- the same encoding; only the instruction class differs.
-- ---------------------------------------------------------------------------

makeGenericJmp :: (SourceType t) => JmpCls -> JmpOp -> Reg -> t -> Int16 -> Instruction
makeGenericJmp cls op dst src off =
  StandardInstruction
    { _opcode = buildOpcodeJmp op (getSrcBit src) cls,
      _dst    = dst,
      _src    = getSrcReg src,
      _off    = off,
      _imm    = getImmVal src
    }

genericJmp64 :: (SourceType t) => JmpOp -> Reg -> t -> Int16 -> Instruction
genericJmp64 = makeGenericJmp BPF_JMP

genericJmp32 :: (SourceType t) => JmpOp -> Reg -> t -> Int16 -> Instruction
genericJmp32 = makeGenericJmp BPF_JMP32

-- ---------------------------------------------------------------------------
-- Unconditional jump (BPF_JA)
--
-- BPF_JMP  | BPF_JA: 32-bit signed offset stored in _imm (larger range).
-- BPF_JMP32 | BPF_JA: 16-bit signed offset stored in _off.
-- Neither variant uses dst or src registers.
-- ---------------------------------------------------------------------------

makeJa64 :: Int32 -> Instruction
makeJa64 imm =
  StandardInstruction
    { _opcode = buildOpcodeJmp BPF_JA BPF_K BPF_JMP,
      _dst    = R0,
      _src    = R0,
      _off    = 0,
      _imm    = imm
    }

makeJa32 :: Int16 -> Instruction
makeJa32 off =
  StandardInstruction
    { _opcode = buildOpcodeJmp BPF_JA BPF_K BPF_JMP32,
      _dst    = R0,
      _src    = R0,
      _off    = off,
      _imm    = 0
    }

-- ---------------------------------------------------------------------------
-- Call and Exit
--
-- BPF_CALL: call a kernel helper function.
--   imm = helper function ID (see kernel's bpf_func_id enum).
--   Registers r1-r5 hold arguments; r0 receives the return value.
--
-- BPF_EXIT: return from the current BPF program.
--   r0 holds the return value.
-- ---------------------------------------------------------------------------

makeCall :: Int32 -> Instruction
makeCall helperID =
  StandardInstruction
    { _opcode = buildOpcodeJmp BPF_CALL BPF_K BPF_JMP,
      _dst    = R0,
      _src    = R0,
      _off    = 0,
      _imm    = helperID
    }

makeExit :: Instruction
makeExit =
  StandardInstruction
    { _opcode = buildOpcodeJmp BPF_EXIT BPF_K BPF_JMP,
      _dst    = R0,
      _src    = R0,
      _off    = 0,
      _imm    = 0
    }

-- ---------------------------------------------------------------------------
-- Load / Store generic builders
--
-- LDX: dst = *(size *)(src + off)   — load from memory into register
--   opcode = BPF_MEM | size | BPF_LDX
--   dst = destination register, src = base-address register, off = byte offset
--
-- ST:  *(size *)(dst + off) = imm   — store sign-extended immediate to memory
--   opcode = BPF_MEM | size | BPF_ST
--   dst = base-address register, src = unused (R0), off = byte offset, imm = value
--
-- STX: *(size *)(dst + off) = src   — store register to memory
--   opcode = BPF_MEM | size | BPF_STX
--   dst = base-address register, src = value register, off = byte offset
--
-- All three use BPF_MEM mode.  The size argument (BPF_B/H/W/DW) selects the
-- transfer width (8, 16, 32, or 64 bits).  Unused fields are zeroed.
-- ---------------------------------------------------------------------------

makeGenericLdx :: LdStSize -> Reg -> Reg -> Int16 -> Instruction
makeGenericLdx size dst src off =
  makeRaw
    (buildOpcodeLd BPF_MEM size BPF_LDX)
    dst
    src
    off
    defaultImmValue

makeGenericSt :: LdStSize -> Reg -> Int16 -> Int32 -> Instruction
makeGenericSt size dst =
  makeRaw
    (buildOpcodeSt BPF_MEM size BPF_ST)
    dst
    R0

makeGenericStx :: LdStSize -> Reg -> Reg -> Int16 -> Instruction
makeGenericStx size dst src off =
  makeRaw
    (buildOpcodeSt BPF_MEM size BPF_STX)
    dst
    src
    off
    defaultImmValue

-- ---------------------------------------------------------------------------
-- Atomic generic builder
--
-- Atomic instructions use BPF_STX class with BPF_ATOMIC mode.  The imm field
-- encodes the operation (ADD/OR/AND/XOR/XCHG/CMPXCHG) and optional FETCH flag.
--
-- *(size *)(dst + off) <op>= src   (basic form)
-- src = atomic_fetch_<op>(dst + off, src)   (FETCH form: old value -> src_reg)
--
-- For CMPXCHG:  if *(dst + off) == R0 then *(dst + off) = src
--               R0 = original value at *(dst + off)
--
-- Only BPF_W (32-bit) and BPF_DW (64-bit) sizes are valid for atomics.
-- ---------------------------------------------------------------------------

makeGenericAtomic :: LdStSize -> Int32 -> Reg -> Reg -> Int16 -> Instruction
makeGenericAtomic size imm dst src off =
  makeRaw
    (buildOpcodeSt BPF_ATOMIC size BPF_STX)
    dst
    src
    off
    imm

-- ---------------------------------------------------------------------------
-- Misc
-- ---------------------------------------------------------------------------

defaultInst :: Instruction
defaultInst =
  StandardInstruction
    { _opcode = 0,
      _dst    = R0,
      _src    = R0,
      _off    = 0,
      _imm    = 0
    }
