module Opcode where

import Data.Bits ((.|.))
import Data.Int (Int32)
import Types

-- Instruction classes
opcodeLd :: Opcode
opcodeLd = 0x00

opcodeLdx :: Opcode
opcodeLdx = 0x01

opcodeSt :: Opcode
opcodeSt = 0x02

opcodeStx :: Opcode
opcodeStx = 0x03

opcodeAlu32 :: Opcode
opcodeAlu32 = 0x04

opcodeJmp64 :: Opcode
opcodeJmp64 = 0x05

opcodeJmp32 :: Opcode
opcodeJmp32 = 0x06

opcodeAlu64 :: Opcode
opcodeAlu64 = 0x07

-- source registers for ALU and JMP
opcodeSrcImm :: Opcode
opcodeSrcImm = 0x00

opcodeSrcReg :: Opcode
opcodeSrcReg = 0x08

-- Byte-order bits for BPF_END instructions.
-- The source bit (bit 3) encodes the byte order target:
--   BPF_TO_LE (0x00) = convert to little-endian  (src = BPF_K)
--   BPF_TO_BE (0x08) = convert to big-endian      (src = BPF_X)
-- These mirror opcodeSrcImm / opcodeSrcReg but are named for END semantics.
opcodeLE :: Opcode
opcodeLE = 0x00   -- BPF_TO_LE

opcodeBE :: Opcode
opcodeBE = 0x08   -- BPF_TO_BE

---------------------------------------------------------------------------------

--- Arithmetic Operations for ALU32 and ALU instructions
opcodeAluAdd :: Opcode
opcodeAluAdd = 0x00

opcodeAluSub :: Opcode
opcodeAluSub = 0x10

opcodeAluMul :: Opcode
opcodeAluMul = 0x20

opcodeAluDiv :: Opcode
opcodeAluDiv = 0x30

opcodeAluSDiv :: Opcode
opcodeAluSDiv = 0x30

opcodeAluOr :: Opcode
opcodeAluOr = 0x40

opcodeAluAnd :: Opcode
opcodeAluAnd = 0x50

opcodeAluLsh :: Opcode
opcodeAluLsh = 0x60

opcodeAluRsh :: Opcode
opcodeAluRsh = 0x70

opcodeAluNeg :: Opcode
opcodeAluNeg = 0x80

opcodeAluMod :: Opcode
opcodeAluMod = 0x90

opcodeAluSMod :: Opcode
opcodeAluSMod = 0x90

opcodeAluXor :: Opcode
opcodeAluXor = 0xA0

opcodeAluMov :: Opcode
opcodeAluMov = 0xB0 -- dst = src

opcodeAluMovSX :: Opcode
opcodeAluMovSX = 0xB0 -- dst = (s8, s16, s32)src

opcodeAluArsh :: Opcode
opcodeAluArsh = 0xC0 -- Sign extending shift right

opcodeAluEnd :: Opcode
opcodeAluEnd = 0xD0 -- Endianness conversion

---------------------------------------------------------------------------------

-- Jump Operations for BPF_JMP32 and BPF_JMP instructions
opcodeJmpJa :: Opcode
opcodeJmpJa = 0x00 -- BPF_JA

opcodeJmpEq :: Opcode
opcodeJmpEq = 0x10 -- BPF_JEQ

opcodeJmpGt :: Opcode
opcodeJmpGt = 0x20 -- BPF_JGT

opcodeJmpGe :: Opcode
opcodeJmpGe = 0x30 -- BPF_JGE

opcodeJmpSet :: Opcode
opcodeJmpSet = 0x40 -- BPF_JSET

opcodeJmpNe :: Opcode
opcodeJmpNe = 0x50 -- BPF_JNE

opcodeJmpSgt :: Opcode
opcodeJmpSgt = 0x60 -- BPF_JSGT

opcodeJmpSge :: Opcode
opcodeJmpSge = 0x70 -- BPF_JSGE

opcodeJmpCall :: Opcode
opcodeJmpCall = 0x80 -- BPF_CALL

opcodeJmpExit :: Opcode
opcodeJmpExit = 0x90 -- BPF_EXIT

opcodeJmpLt :: Opcode
opcodeJmpLt = 0xA0 -- BPF_JLT

opcodeJmpLe :: Opcode
opcodeJmpLe = 0xB0 -- BPF_JLE

opcodeJmpSlt :: Opcode
opcodeJmpSlt = 0xC0 -- BPF_JSLT

opcodeJmpSle :: Opcode
opcodeJmpSle = 0xD0 -- BPF_JSLE

---------------------------------------------------------------------------------

-- Mode and Size of Load and Store instructions
opcodeModeImm :: Opcode
opcodeModeImm = 0x00

opcodeModeAbs :: Opcode
opcodeModeAbs = 0x20

opcodeModeInd :: Opcode
opcodeModeInd = 0x40

opcodeModeMem :: Opcode
opcodeModeMem = 0x60

opcodeModeAtomic :: Opcode
opcodeModeAtomic = 0xC0

opcodeLdStW :: Opcode
opcodeLdStW = 0x00

opcodeLdStH :: Opcode
opcodeLdStH = 0x08

opcodeLdStB :: Opcode
opcodeLdStB = 0x10

opcodeLdStDW :: Opcode
opcodeLdStDW = 0x18

---------------------------------------------------------------------------------

-- Helpers for getting the opcode of instruction classes
getAluClsOpcode :: AluCls -> Opcode
getAluClsOpcode cls = case cls of
  BPF_ALU -> opcodeAlu32
  BPF_ALU64 -> opcodeAlu64

getOpcodeLoad :: LoadCls -> Opcode
getOpcodeLoad cls = case cls of
  BPF_LD -> opcodeLd
  BPF_LDX -> opcodeLdx

getOpcodeStore :: StoreCls -> Opcode
getOpcodeStore cls = case cls of
  BPF_ST -> opcodeSt
  BPF_STX -> opcodeStx

getJmpClsOpcode :: JmpCls -> Opcode
getJmpClsOpcode cls = case cls of
  BPF_JMP -> opcodeJmp64
  BPF_JMP32 -> opcodeJmp32

-- Helper for getting the source operand
getSrcOpcode :: SrcType -> Opcode
getSrcOpcode src = case src of
  BPF_K -> opcodeSrcImm
  BPF_X -> opcodeSrcReg

-- Helper for getting airthmetic operation opcode
getAluOpcode :: AluOp -> Opcode
getAluOpcode op = case op of
  BPF_ADD -> opcodeAluAdd
  BPF_SUB -> opcodeAluSub
  BPF_MUL -> opcodeAluMul
  BPF_DIV -> opcodeAluDiv
  BPF_SDIV -> opcodeAluSDiv
  BPF_OR -> opcodeAluOr
  BPF_AND -> opcodeAluAnd
  BPF_XOR -> opcodeAluXor
  BPF_LSH -> opcodeAluLsh
  BPF_RSH -> opcodeAluRsh
  BPF_NEG -> opcodeAluNeg
  BPF_MOD -> opcodeAluMod
  BPF_SMOD -> opcodeAluSMod
  BPF_MOV -> opcodeAluMov
  BPF_MOVSX -> opcodeAluMovSX
  BPF_ARSH -> opcodeAluArsh
  BPF_END -> opcodeAluEnd

-- Helper for getting the Jmp instructions _opcode
getJmpOpcode :: JmpOp -> Opcode
getJmpOpcode op = case op of
  BPF_JA -> opcodeJmpJa
  BPF_JEQ -> opcodeJmpEq
  BPF_JGT -> opcodeJmpGt
  BPF_JGE -> opcodeJmpGe
  BPF_JSET -> opcodeJmpSet
  BPF_JNE -> opcodeJmpNe
  BPF_JSGT -> opcodeJmpSgt
  BPF_JSGE -> opcodeJmpSge
  BPF_CALL -> opcodeJmpCall
  BPF_EXIT -> opcodeJmpExit
  BPF_JLT -> opcodeJmpLt
  BPF_JLE -> opcodeJmpLe
  BPF_JSLT -> opcodeJmpSlt
  BPF_JSLE -> opcodeJmpSle

-- Helper for getting Load and Store size
getLdStSize :: LdStSize -> Opcode
getLdStSize size = case size of
  BPF_W -> opcodeLdStW
  BPF_H -> opcodeLdStH
  BPF_B -> opcodeLdStB
  BPF_DW -> opcodeLdStDW

-- Helper for getting Load and Store module
getLdStMode :: LdStMode -> Opcode
getLdStMode mode = case mode of
  BPF_IMM -> opcodeModeImm
  BPF_ABS -> opcodeModeAbs
  BPF_IND -> opcodeModeInd
  BPF_MEM -> opcodeModeMem
  BPF_ATOMIC -> opcodeModeAtomic

-- opcode builders
buildOpcodeAlu :: AluOp -> SrcType -> AluCls -> Opcode
buildOpcodeAlu op src cls = getAluOpcode op .|. getSrcOpcode src .|. getAluClsOpcode cls

buildOpcodeJmp :: JmpOp -> SrcType -> JmpCls -> Opcode
buildOpcodeJmp op src cls = getJmpOpcode op .|. getSrcOpcode src .|. getJmpClsOpcode cls

buildOpcodeLd :: LdStMode -> LdStSize -> LoadCls -> Opcode
buildOpcodeLd mode size cls = getLdStMode mode .|. getLdStSize size .|. getOpcodeLoad cls

buildOpcodeSt :: LdStMode -> LdStSize -> StoreCls -> Opcode
buildOpcodeSt mode size cls = getLdStMode mode .|. getLdStSize size .|. getOpcodeStore cls

-- Map a byte-order target to its src-bit value in the opcode.
-- BPF_END encodes target endianness in bit 3 (the source bit):
--   LittleEndian -> 0x00 (BPF_K / BPF_TO_LE)
--   BigEndian    -> 0x08 (BPF_X / BPF_TO_BE)
getByteOrderOpcode :: SrcByteOrder -> Opcode
getByteOrderOpcode bo = case bo of
  LittleEndian -> opcodeLE
  BigEndian    -> opcodeBE

-- Build the opcode for BPF_END (to-LE / to-BE) and BPF_ALU64+END (bswap).
-- For BPF_ALU  | BPF_END: byte-order is encoded via bo; imm carries the width.
-- For BPF_ALU64 | BPF_END (bswap): byte-order must be LittleEndian (src=0).
buildOpcodeEnd :: SrcByteOrder -> AluCls -> Opcode
buildOpcodeEnd bo cls = opcodeAluEnd .|. getByteOrderOpcode bo .|. getAluClsOpcode cls

---------------------------------------------------------------------------------

-- Atomic operation imm-field values (RFC 9669 §5.3)
--
-- Atomic instructions use BPF_STX class with BPF_ATOMIC mode.  The imm field
-- encodes which atomic operation to perform.  XCHG and CMPXCHG always include
-- the FETCH flag; for ADD/OR/AND/XOR the FETCH flag is optional.
--
-- Available sizes: BPF_W (32-bit) and BPF_DW (64-bit).

getAtomicImm :: AtomicOp -> Int32
getAtomicImm op = case op of
  ATOMIC_ADD     -> 0x00
  ATOMIC_OR      -> 0x40
  ATOMIC_AND     -> 0x50
  ATOMIC_XOR     -> 0xA0
  ATOMIC_XCHG    -> 0xE1   -- 0xE0 | FETCH (always fetches)
  ATOMIC_CMPXCHG -> 0xF1   -- 0xF0 | FETCH (always fetches)

-- The FETCH flag (bit 0 of imm).  When set, the original value at the memory
-- location is written back to src_reg (or R0 for CMPXCHG).
atomicFetchFlag :: Int32
atomicFetchFlag = 0x01

-- Combine an atomic operation with the FETCH flag.
getAtomicFetchImm :: AtomicOp -> Int32
getAtomicFetchImm op = getAtomicImm op .|. atomicFetchFlag
