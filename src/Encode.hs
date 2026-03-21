module Encode where

import Data.Bits (shiftL, (.|.))
import Data.ByteString.Builder
import Data.Word (Word8)
import Types

convertRegToWord8 :: Reg -> Word8
convertRegToWord8 reg = fromIntegral (fromEnum reg)

-- Pack two 4-bit register numbers into a single byte.
-- Layout: src_reg in the high nibble, dst_reg in the low nibble.
packRegisters :: Reg -> Reg -> Word8
packRegisters src dst =
  (convertRegToWord8 src `shiftL` 4) .|. convertRegToWord8 dst

-- Encode a single instruction to its binary representation.
--
-- StandardInstruction  → 8 bytes  (one 64-bit eBPF instruction)
-- ExtendedInstruction  → 16 bytes (two consecutive 64-bit words)
--
-- The extended format is used for wide instructions such as BPF_LD_IMM64.
-- The second 64-bit word carries _res (must be zero) and _imm_next.
encodeInstruction :: Instruction -> Builder
encodeInstruction (StandardInstruction op dst src off imm) =
  word8 op
    <> word8 (packRegisters src dst)
    <> int16LE off
    <> int32LE imm
encodeInstruction (ExtendedInstruction op dst src off imm res imm_next) =
  word8 op
    <> word8 (packRegisters src dst)
    <> int16LE off
    <> int32LE imm
    <> int32LE res
    <> int32LE imm_next

-- Encode a list of instructions into a single Builder.
-- ExtendedInstructions in the list contribute 16 bytes each; all others 8.
encodeProgram :: [Instruction] -> Builder
encodeProgram instrs = mconcat (map encodeInstruction instrs)
