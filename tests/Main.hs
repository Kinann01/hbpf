module Main where

import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString.Lazy as BL
import Data.Word (Word8, Word64)
import Encode
import Helpers
import Instructions
import qualified Program as P
import Test.Tasty
import Test.Tasty.HUnit
import Types

-- Encode a single instruction to a flat list of bytes for easy comparison.
encodeBytes :: Instruction -> [Word8]
encodeBytes = BL.unpack . toLazyByteString . encodeInstruction

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "hbpf"
    [ aluTests
    , movTests
    , endTests
    , jmpTests
    , ldStTests
    , atomicTests
    , helperTests
    , extendedTests
    , programTests
    ]

-- ---------------------------------------------------------------------------
-- ALU
-- ---------------------------------------------------------------------------

aluTests :: TestTree
aluTests =
  testGroup
    "ALU"
    [ testCase "bpf_add64 R0 R1 (reg src)" $
        encodeBytes (bpf_add64 R0 R1)
          @?= [0x0F, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_add64 R0 23 (imm src)" $
        encodeBytes (bpf_add64 R0 (23 :: Int))
          @?= [0x07, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00]
    , testCase "bpf_add32 R0 23 (imm src, 32-bit class)" $
        encodeBytes (bpf_add32 R0 (23 :: Int))
          @?= [0x04, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00]
    , testCase "bpf_sub64 R3 R4 (reg src)" $
        encodeBytes (bpf_sub64 R3 R4)
          @?= [0x1F, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_mul32 R1 R2" $
        encodeBytes (bpf_mul32 R1 R2)
          @?= [0x2C, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_div64 R0 R1 (unsigned, off=0)" $
        encodeBytes (bpf_div64 R0 R1)
          @?= [0x3F, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_sdiv64 R0 R1 (signed, off=1)" $
        encodeBytes (bpf_sdiv64 R0 R1)
          @?= [0x3F, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_mod64 R0 R1 (unsigned, off=0)" $
        encodeBytes (bpf_mod64 R0 R1)
          @?= [0x9F, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_smod64 R0 R1 (signed, off=1)" $
        encodeBytes (bpf_smod64 R0 R1)
          @?= [0x9F, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_or64 R5 R6" $
        encodeBytes (bpf_or64 R5 R6)
          @?= [0x4F, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_and64 R0 255 (imm)" $
        encodeBytes (bpf_and64 R0 (255 :: Int))
          @?= [0x57, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00]
    , testCase "bpf_lsh64 R1 R2" $
        encodeBytes (bpf_lsh64 R1 R2)
          @?= [0x6F, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_rsh64 R1 3 (imm)" $
        encodeBytes (bpf_rsh64 R1 (3 :: Int))
          @?= [0x77, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]
    , testCase "bpf_arsh64 R2 R3" $
        encodeBytes (bpf_arsh64 R2 R3)
          @?= [0xCF, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_xor64 R0 R0 (zero a register)" $
        encodeBytes (bpf_xor64 R0 R0)
          @?= [0xAF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_neg64 R2 (unary, no src)" $
        encodeBytes (bpf_neg64 R2)
          @?= [0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_neg32 R0" $
        encodeBytes (bpf_neg32 R0)
          @?= [0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    ]

-- ---------------------------------------------------------------------------
-- MOV / MOVSX
-- ---------------------------------------------------------------------------

movTests :: TestTree
movTests =
  testGroup
    "MOV"
    [ testCase "bpf_mov64 R1 42 (imm)" $
        encodeBytes (bpf_mov64 R1 (42 :: Int))
          @?= [0xB7, 0x01, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00]
    , testCase "bpf_mov64 R2 R3 (reg)" $
        encodeBytes (bpf_mov64 R2 R3)
          @?= [0xBF, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_mov32 R0 0 (imm zero)" $
        encodeBytes (bpf_mov32 R0 (0 :: Int))
          @?= [0xB4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_movSX64 R0 R1 Ext8 (sign-extend 8 bits)" $
        encodeBytes (bpf_movSX64 R0 R1 Ext8)
          @?= [0xBF, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_movSX64 R0 R1 Ext16" $
        encodeBytes (bpf_movSX64 R0 R1 Ext16)
          @?= [0xBF, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_movSX64 R0 R1 Ext32" $
        encodeBytes (bpf_movSX64 R0 R1 Ext32)
          @?= [0xBF, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]
    ]

-- ---------------------------------------------------------------------------
-- END / BSWAP
-- ---------------------------------------------------------------------------

endTests :: TestTree
endTests =
  testGroup
    "END / BSWAP"
    [ testCase "bpf_tole R0 Width16 (to little-endian)" $
        encodeBytes (bpf_tole R0 Width16)
          @?= [0xD4, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]
    , testCase "bpf_tole R0 Width32" $
        encodeBytes (bpf_tole R0 Width32)
          @?= [0xD4, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]
    , testCase "bpf_toBe R1 Width32 (to big-endian)" $
        encodeBytes (bpf_toBe R1 Width32)
          @?= [0xDC, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]
    , testCase "bpf_toBe R0 Width64" $
        encodeBytes (bpf_toBe R0 Width64)
          @?= [0xDC, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
    , testCase "bpf_bswap R2 Width64 (unconditional swap)" $
        encodeBytes (bpf_bswap R2 Width64)
          @?= [0xD7, 0x02, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
    ]

-- ---------------------------------------------------------------------------
-- JMP
-- ---------------------------------------------------------------------------

jmpTests :: TestTree
jmpTests =
  testGroup
    "JMP"
    [ testCase "bpf_exit" $
        encodeBytes bpf_exit
          @?= [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_call 6 (helper id in imm)" $
        encodeBytes (bpf_call 6)
          @?= [0x85, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00]
    , testCase "bpf_ja 100 (unconditional, offset in imm)" $
        encodeBytes (bpf_ja 100)
          @?= [0x05, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00]
    , testCase "bpf_ja32 (-3) (unconditional, offset in off)" $
        encodeBytes (bpf_ja32 (-3))
          @?= [0x06, 0x00, 0xFD, 0xFF, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_jeq64 R0 R1 4 (reg src)" $
        encodeBytes (bpf_jeq64 R0 R1 4)
          @?= [0x1D, 0x10, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_jeq64 R0 0 (-2) (imm src)" $
        encodeBytes (bpf_jeq64 R0 (0 :: Int) (-2))
          @?= [0x15, 0x00, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_jne64 R1 R2 10" $
        encodeBytes (bpf_jne64 R1 R2 10)
          @?= [0x5D, 0x21, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_jgt32 R0 R1 1 (32-bit class)" $
        encodeBytes (bpf_jgt32 R0 R1 1)
          @?= [0x2E, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_jslt64 R3 R4 (-1)" $
        encodeBytes (bpf_jslt64 R3 R4 (-1))
          @?= [0xCD, 0x43, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]
    ]

-- ---------------------------------------------------------------------------
-- LD / LDX / ST / STX
-- ---------------------------------------------------------------------------

ldStTests :: TestTree
ldStTests =
  testGroup
    "LD / LDX / ST / STX"
    [ testCase "bpf_ldx64 R1 R10 (-8)" $
        encodeBytes (bpf_ldx64 R1 R10 (-8))
          @?= [0x79, 0xA1, 0xF8, 0xFF, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_ldx32 R0 R1 0" $
        encodeBytes (bpf_ldx32 R0 R1 0)
          @?= [0x61, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_ldx16 R0 R1 4" $
        encodeBytes (bpf_ldx16 R0 R1 4)
          @?= [0x69, 0x10, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_ldx8 R0 R1 0" $
        encodeBytes (bpf_ldx8 R0 R1 0)
          @?= [0x71, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_stx64 R10 R1 (-8)" $
        encodeBytes (bpf_stx64 R10 R1 (-8))
          @?= [0x7B, 0x1A, 0xF8, 0xFF, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_stx32 R10 R2 (-4)" $
        encodeBytes (bpf_stx32 R10 R2 (-4))
          @?= [0x63, 0x2A, 0xFC, 0xFF, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_st64 R10 (-8) 0 (store imm zero)" $
        encodeBytes (bpf_st64 R10 (-8) 0)
          @?= [0x7A, 0x0A, 0xF8, 0xFF, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_st32 R10 (-4) 0" $
        encodeBytes (bpf_st32 R10 (-4) 0)
          @?= [0x62, 0x0A, 0xFC, 0xFF, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_st32 R1 8 42 (store imm value)" $
        encodeBytes (bpf_st32 R1 8 42)
          @?= [0x62, 0x01, 0x08, 0x00, 0x2A, 0x00, 0x00, 0x00]
    , testCase "bpf_st8 R1 0 255" $
        encodeBytes (bpf_st8 R1 0 255)
          @?= [0x72, 0x01, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00]
    ]

-- ---------------------------------------------------------------------------
-- Atomic
-- ---------------------------------------------------------------------------

atomicTests :: TestTree
atomicTests =
  testGroup
    "Atomic"
    [ -- Basic (no fetch) — 64-bit
      testCase "bpf_atomic_add64 R10 R1 (-8)" $
        -- opcode = BPF_ATOMIC | BPF_DW | BPF_STX = 0xC0 | 0x18 | 0x03 = 0xDB
        -- imm = ATOMIC_ADD = 0x00
        encodeBytes (bpf_atomic_add64 R10 R1 (-8))
          @?= [0xDB, 0x1A, 0xF8, 0xFF, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_atomic_add32 R10 R2 (-4)" $
        -- opcode = BPF_ATOMIC | BPF_W | BPF_STX = 0xC0 | 0x00 | 0x03 = 0xC3
        encodeBytes (bpf_atomic_add32 R10 R2 (-4))
          @?= [0xC3, 0x2A, 0xFC, 0xFF, 0x00, 0x00, 0x00, 0x00]
    , testCase "bpf_atomic_or64 R1 R2 0" $
        -- imm = ATOMIC_OR = 0x40
        encodeBytes (bpf_atomic_or64 R1 R2 0)
          @?= [0xDB, 0x21, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
    , testCase "bpf_atomic_and64 R1 R3 8" $
        -- imm = ATOMIC_AND = 0x50
        encodeBytes (bpf_atomic_and64 R1 R3 8)
          @?= [0xDB, 0x31, 0x08, 0x00, 0x50, 0x00, 0x00, 0x00]
    , testCase "bpf_atomic_xor32 R1 R4 0" $
        -- imm = ATOMIC_XOR = 0xA0
        encodeBytes (bpf_atomic_xor32 R1 R4 0)
          @?= [0xC3, 0x41, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00]
      -- Fetch variants
    , testCase "bpf_atomic_fetch_add64 R10 R1 (-8)" $
        -- imm = ATOMIC_ADD | FETCH = 0x00 | 0x01 = 0x01
        encodeBytes (bpf_atomic_fetch_add64 R10 R1 (-8))
          @?= [0xDB, 0x1A, 0xF8, 0xFF, 0x01, 0x00, 0x00, 0x00]
    , testCase "bpf_atomic_fetch_or32 R1 R2 0" $
        -- imm = ATOMIC_OR | FETCH = 0x40 | 0x01 = 0x41
        encodeBytes (bpf_atomic_fetch_or32 R1 R2 0)
          @?= [0xC3, 0x21, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00]
    , testCase "bpf_atomic_fetch_and64 R1 R3 0" $
        -- imm = ATOMIC_AND | FETCH = 0x50 | 0x01 = 0x51
        encodeBytes (bpf_atomic_fetch_and64 R1 R3 0)
          @?= [0xDB, 0x31, 0x00, 0x00, 0x51, 0x00, 0x00, 0x00]
    , testCase "bpf_atomic_fetch_xor64 R1 R4 0" $
        -- imm = ATOMIC_XOR | FETCH = 0xA0 | 0x01 = 0xA1
        encodeBytes (bpf_atomic_fetch_xor64 R1 R4 0)
          @?= [0xDB, 0x41, 0x00, 0x00, 0xA1, 0x00, 0x00, 0x00]
      -- Exchange (always fetches)
    , testCase "bpf_atomic_xchg64 R10 R1 (-8)" $
        -- imm = ATOMIC_XCHG = 0xE1
        encodeBytes (bpf_atomic_xchg64 R10 R1 (-8))
          @?= [0xDB, 0x1A, 0xF8, 0xFF, 0xE1, 0x00, 0x00, 0x00]
    , testCase "bpf_atomic_xchg32 R1 R2 0" $
        encodeBytes (bpf_atomic_xchg32 R1 R2 0)
          @?= [0xC3, 0x21, 0x00, 0x00, 0xE1, 0x00, 0x00, 0x00]
      -- Compare and exchange (always fetches)
    , testCase "bpf_atomic_cmpxchg64 R10 R1 (-8)" $
        -- imm = ATOMIC_CMPXCHG = 0xF1
        encodeBytes (bpf_atomic_cmpxchg64 R10 R1 (-8))
          @?= [0xDB, 0x1A, 0xF8, 0xFF, 0xF1, 0x00, 0x00, 0x00]
    , testCase "bpf_atomic_cmpxchg32 R1 R3 4" $
        encodeBytes (bpf_atomic_cmpxchg32 R1 R3 4)
          @?= [0xC3, 0x31, 0x04, 0x00, 0xF1, 0x00, 0x00, 0x00]
    ]

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

helperTests :: TestTree
helperTests =
  testGroup
    "Helpers"
    [ -- All helpers emit BPF_CALL (opcode 0x85), regs=0x00, off=0x0000.
      -- Only the imm field (helper ID) varies.
      testCase "helper_map_lookup_elem (id=1)" $
        encodeBytes helper_map_lookup_elem
          @?= [0x85, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
    , testCase "helper_map_update_elem (id=2)" $
        encodeBytes helper_map_update_elem
          @?= [0x85, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]
    , testCase "helper_map_delete_elem (id=3)" $
        encodeBytes helper_map_delete_elem
          @?= [0x85, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]
    , testCase "helper_ktime_get_ns (id=5)" $
        encodeBytes helper_ktime_get_ns
          @?= [0x85, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00]
    , testCase "helper_trace_printk (id=6)" $
        encodeBytes helper_trace_printk
          @?= [0x85, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00]
    , testCase "helper_get_prandom_u32 (id=7)" $
        encodeBytes helper_get_prandom_u32
          @?= [0x85, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00]
    , testCase "helper_get_current_pid_tgid (id=14)" $
        encodeBytes helper_get_current_pid_tgid
          @?= [0x85, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00]
    , testCase "helper_ringbuf_output (id=130)" $
        encodeBytes helper_ringbuf_output
          @?= [0x85, 0x00, 0x00, 0x00, 0x82, 0x00, 0x00, 0x00]
    , testCase "helper is equivalent to bpf_call with same ID" $
        encodeBytes helper_trace_printk
          @?= encodeBytes (bpf_call 6)
    ]

-- ---------------------------------------------------------------------------
-- Extended (128-bit) instruction — bpf_ld_imm64
-- ---------------------------------------------------------------------------

extendedTests :: TestTree
extendedTests =
  testGroup
    "Extended (128-bit)"
    [ testCase "bpf_ld_imm64 R1 0x00000001FFFFFFFF" $
        encodeBytes (bpf_ld_imm64 R1 0x00000001FFFFFFFF)
          @?= [ 0x18, 0x01, 0x00, 0x00  -- opcode, regs, off
              , 0xFF, 0xFF, 0xFF, 0xFF  -- imm = lower 32 bits
              , 0x00, 0x00, 0x00, 0x00  -- reserved
              , 0x01, 0x00, 0x00, 0x00  -- imm_next = upper 32 bits
              ]
    , testCase "bpf_ld_imm64 R0 0 (zero constant)" $
        encodeBytes (bpf_ld_imm64 R0 0)
          @?= [ 0x18, 0x00, 0x00, 0x00
              , 0x00, 0x00, 0x00, 0x00
              , 0x00, 0x00, 0x00, 0x00
              , 0x00, 0x00, 0x00, 0x00
              ]
    , testCase "bpf_ld_imm64 R2 0xDEADBEEFCAFEBABE (full 64-bit constant)" $
        encodeBytes (bpf_ld_imm64 R2 (fromIntegral (0xDEADBEEFCAFEBABE :: Word64)))
          @?= [ 0x18, 0x02, 0x00, 0x00
              , 0xBE, 0xBA, 0xFE, 0xCA  -- lower 32 bits of 0xCAFEBABE
              , 0x00, 0x00, 0x00, 0x00
              , 0xEF, 0xBE, 0xAD, 0xDE  -- upper 32 bits of 0xDEADBEEF
              ]
    , testCase "encodeProgram produces correct total size for mixed program" $
        let prog = [ bpf_mov64 R1 (1 :: Int)   -- 8 bytes
                   , bpf_ld_imm64 R2 0xFFFF     -- 16 bytes
                   , bpf_exit                   -- 8 bytes
                   ]
            bytes = BL.length (toLazyByteString (encodeProgram prog))
        in bytes @?= 32
    ]

-- ---------------------------------------------------------------------------
-- Program (monad)
-- ---------------------------------------------------------------------------

-- | Helper: encode a list of instructions to flat bytes for comparison.
encodeProgramBytes :: [Instruction] -> [Word8]
encodeProgramBytes = BL.unpack . toLazyByteString . encodeProgram

programTests :: TestTree
programTests =
  testGroup
    "Program (monad)"
    [ testCase "simple program (no labels)" $
        let result = P.assemble $ do
              P.mov64 R0 (0 :: Int)
              P.exit
        in case result of
             Left e   -> assertFailure e
             Right is -> is @?= [ bpf_mov64 R0 (0 :: Int)
                                 , bpf_exit
                                 ]

    , testCase "forward jump" $
        -- mov64 R0 0     -- PC 0
        -- jeq64 R1 0 end -- PC 1, jump to PC 3 → offset = 3 - (1+1) = 1
        -- mov64 R0 1     -- PC 2
        -- label end:     -- PC 3
        -- exit           -- PC 3
        let result = P.assemble $ do
              end <- P.newLabel
              P.mov64 R0 (0 :: Int)
              P.jeq64 R1 (0 :: Int) end
              P.mov64 R0 (1 :: Int)
              P.label end
              P.exit
        in case result of
             Left e   -> assertFailure e
             Right is -> is @?= [ bpf_mov64 R0 (0 :: Int)
                                 , bpf_jeq64 R1 (0 :: Int) 1
                                 , bpf_mov64 R0 (1 :: Int)
                                 , bpf_exit
                                 ]

    , testCase "backward jump (loop)" $
        -- label top:      -- PC 0
        -- add64 R0 1      -- PC 0
        -- jlt64 R0 10 top -- PC 1, jump to PC 0 → offset = 0 - (1+1) = -2
        -- exit             -- PC 2
        let result = P.assemble $ do
              top <- P.newLabel
              P.label top
              P.add64 R0 (1 :: Int)
              P.jlt64 R0 (10 :: Int) top
              P.exit
        in case result of
             Left e   -> assertFailure e
             Right is -> is @?= [ bpf_add64 R0 (1 :: Int)
                                 , bpf_jlt64 R0 (10 :: Int) (-2)
                                 , bpf_exit
                                 ]

    , testCase "unconditional jump (ja)" $
        -- ja skip         -- PC 0, jump to PC 2 → offset = 2 - (0+1) = 1
        -- mov64 R0 0      -- PC 1
        -- label skip:     -- PC 2
        -- exit            -- PC 2
        let result = P.assemble $ do
              skip <- P.newLabel
              P.ja skip
              P.mov64 R0 (0 :: Int)
              P.label skip
              P.exit
        in case result of
             Left e   -> assertFailure e
             Right is -> is @?= [ bpf_ja 1
                                 , bpf_mov64 R0 (0 :: Int)
                                 , bpf_exit
                                 ]

    , testCase "wide instruction (ld_imm64) counts as 2 PC slots" $
        -- ldImm64 R1 42  -- PC 0 (wide, occupies slots 0 and 1)
        -- ja end         -- PC 2, jump to PC 4 → offset = 4 - (2+1) = 1
        -- mov64 R0 0     -- PC 3
        -- label end:     -- PC 4
        -- exit           -- PC 4
        let result = P.assemble $ do
              end <- P.newLabel
              P.ldImm64 R1 42
              P.ja end
              P.mov64 R0 (0 :: Int)
              P.label end
              P.exit
        in case result of
             Left e   -> assertFailure e
             Right is -> is @?= [ bpf_ld_imm64 R1 42
                                 , bpf_ja 1
                                 , bpf_mov64 R0 (0 :: Int)
                                 , bpf_exit
                                 ]

    , testCase "backward jump over wide instruction" $
        -- label top:     -- PC 0
        -- ldImm64 R1 99  -- PC 0 (wide, slots 0-1)
        -- add64 R0 R1    -- PC 2
        -- jlt64 R0 R2 top -- PC 3, jump to PC 0 → offset = 0 - (3+1) = -4
        -- exit            -- PC 4
        let result = P.assemble $ do
              top <- P.newLabel
              P.label top
              P.ldImm64 R1 99
              P.add64 R0 R1
              P.jlt64 R0 R2 top
              P.exit
        in case result of
             Left e   -> assertFailure e
             Right is -> is @?= [ bpf_ld_imm64 R1 99
                                 , bpf_add64 R0 R1
                                 , bpf_jlt64 R0 R2 (-4)
                                 , bpf_exit
                                 ]

    , testCase "multiple labels" $
        -- jeq64 R0 0 zero  -- PC 0, → PC 3, offset = 3 - (0+1) = 2
        -- mov64 R0 1       -- PC 1
        -- ja done           -- PC 2, → PC 4, offset = 4 - (2+1) = 1
        -- label zero:      -- PC 3
        -- mov64 R0 0       -- PC 3
        -- label done:      -- PC 4
        -- exit             -- PC 4
        let result = P.assemble $ do
              zero <- P.newLabel
              done <- P.newLabel
              P.jeq64 R0 (0 :: Int) zero
              P.mov64 R0 (1 :: Int)
              P.ja done
              P.label zero
              P.mov64 R0 (0 :: Int)
              P.label done
              P.exit
        in case result of
             Left e   -> assertFailure e
             Right is -> is @?= [ bpf_jeq64 R0 (0 :: Int) 2
                                 , bpf_mov64 R0 (1 :: Int)
                                 , bpf_ja 1
                                 , bpf_mov64 R0 (0 :: Int)
                                 , bpf_exit
                                 ]

    , testCase "undefined label produces Left" $
        let result = P.assemble $ do
              ghost <- P.newLabel
              P.ja ghost
              P.exit
        in case result of
             Left _  -> return ()
             Right _ -> assertFailure "expected Left for undefined label"

    , testCase "monadic program encodes identically to Layer 1" $
        let layer1 = [ bpf_mov64 R1 (1 :: Int)
                      , bpf_add64 R1 (2 :: Int)
                      , bpf_mov64 R0 R1
                      , bpf_exit
                      ]
            layer2 = P.assemble $ do
                       P.mov64 R1 (1 :: Int)
                       P.add64 R1 (2 :: Int)
                       P.mov64 R0 R1
                       P.exit
        in case layer2 of
             Left e   -> assertFailure e
             Right is -> encodeProgramBytes is @?= encodeProgramBytes layer1
    ]
