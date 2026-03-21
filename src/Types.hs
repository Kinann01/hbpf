{-# LANGUAGE DuplicateRecordFields #-}

module Types where

import Data.Int (Int16, Int32)
import Data.Word (Word8)

type Opcode = Word8

-- Needed for the MOVSX instruction for size of src
-- MOVSX (dst = (s8,s16,s32)src)
data ExtensionSize
  = Ext0
  | Ext8
  | Ext16
  | Ext32
  deriving (Show, Eq)

-- Needed for END instructions which are Byte Swap Instructions
data EndianWidth
  = Width16
  | Width32
  | Width64
  deriving (Show, Eq)

-- Needed for encoding source in the opcode 8 bit instruction
-- This replaces the SrcType with SrcByteOrder
-- Where for ALU, LE is 0 while BE is 1 and for ALU64, swap unconditionally
data SrcByteOrder
  = BigEndian
  | LittleEndian
  deriving (Show, Eq)

-- General purpose registers R0-R9
-- R10 is read-only for frame pointer
data Reg
  = R0
  | R1
  | R2
  | R3
  | R4
  | R5
  | R6
  | R7
  | R8
  | R9
  | R10
  deriving (Show, Eq, Enum)

-- Arithmetic class and operations
data AluCls
  = BPF_ALU -- 32-bit arithmetic operations
  | BPF_ALU64 -- 64-bit arithmetic operations
  deriving (Show, Eq)

data AluOp
  = BPF_ADD
  | BPF_SUB
  | BPF_MUL
  | BPF_DIV
  | BPF_SDIV
  | BPF_OR
  | BPF_AND
  | BPF_LSH
  | BPF_RSH
  | BPF_NEG
  | BPF_MOD
  | BPF_SMOD
  | BPF_XOR
  | BPF_MOV
  | BPF_MOVSX
  | BPF_ARSH
  | BPF_END
  deriving (Show, Eq)

-- Jump Class and operations
data JmpCls
  = BPF_JMP -- 64-bit jump operation
  | BPF_JMP32 -- 32-bit jump operation
  deriving (Show, Eq)

data JmpOp
  = BPF_JA
  | BPF_JEQ
  | BPF_JGT
  | BPF_JGE
  | BPF_JSET
  | BPF_JNE
  | BPF_JSGT
  | BPF_JSGE
  | BPF_CALL
  | BPF_EXIT
  | BPF_JLT
  | BPF_JLE
  | BPF_JSLT
  | BPF_JSLE
  deriving (Show, Eq)

-- Source operand type used by jmp and alu instructions
data SrcType
  = BPF_K -- use 32-bit immediat
  | BPF_X -- use 'src_reg' register
  deriving (Show, Eq)

-- Load and store instruction class, size and mode
data LoadCls
  = BPF_LD -- non-standard load operations
  | BPF_LDX -- load into register operations
  deriving (Show, Eq)

data StoreCls
  = BPF_ST -- store from immediate operations
  | BPF_STX -- store from register operations
  deriving (Show, Eq)

data LdStSize
  = BPF_W -- word
  | BPF_H -- half-word
  | BPF_B -- byte
  | BPF_DW -- double-word
  deriving (Show, Eq)

data LdStMode
  = BPF_IMM -- 64-bit immediate instructions
  | BPF_ABS -- legacy BPF packet access (absolute)
  | BPF_IND -- legacy BPF packet access (indirect)
  | BPF_MEM -- regular load and store operations
  | BPF_ATOMIC -- atomic operations
  deriving (Show, Eq)

-- Atomic operations encoded in the imm field of BPF_ATOMIC instructions.
-- XCHG and CMPXCHG always include the FETCH flag (0x01).
data AtomicOp
  = ATOMIC_ADD
  | ATOMIC_OR
  | ATOMIC_AND
  | ATOMIC_XOR
  | ATOMIC_XCHG
  | ATOMIC_CMPXCHG
  deriving (Show, Eq)

data Instruction
  = StandardInstruction
      { _opcode :: Word8,
        _dst :: Reg,
        _src :: Reg,
        _off :: Int16,
        _imm :: Int32
      }
  | ExtendedInstruction
      { _opcode :: Word8,
        _dst :: Reg,
        _src :: Reg,
        _off :: Int16,
        _imm :: Int32,
        _res :: Int32,
        _imm_next :: Int32
      }
  deriving (Show, Eq)
