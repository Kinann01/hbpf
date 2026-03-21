module Program
  ( -- * BPF program builder monad
    BPF
  , assemble

    -- * Labels
  , Label
  , newLabel
  , label

    -- * Raw instruction emission
  , emit

    -- * ALU operations
  , add64, add32, sub64, sub32
  , mul64, mul32
  , div64, div32, sdiv64, sdiv32
  , mod64, mod32, smod64, smod32
  , or64, or32, and64, and32, xor64, xor32
  , lsh64, lsh32, rsh64, rsh32, arsh64, arsh32
  , neg64, neg32

    -- * Move
  , mov64, mov32
  , movSX64, movSX32

    -- * Byte swap
  , tole, toBe, bswap

    -- * Load / Store
  , ldx64, ldx32, ldx16, ldx8
  , st64, st32, st16, st8
  , stx64, stx32, stx16, stx8
  , ldImm64

    -- * Atomic
  , atomicAdd64, atomicAdd32
  , atomicOr64, atomicOr32
  , atomicAnd64, atomicAnd32
  , atomicXor64, atomicXor32
  , atomicFetchAdd64, atomicFetchAdd32
  , atomicFetchOr64, atomicFetchOr32
  , atomicFetchAnd64, atomicFetchAnd32
  , atomicFetchXor64, atomicFetchXor32
  , atomicXchg64, atomicXchg32
  , atomicCmpxchg64, atomicCmpxchg32

    -- * Jumps (with labels)
  , jeq64, jeq32, jne64, jne32
  , jgt64, jgt32, jge64, jge32
  , jlt64, jlt32, jle64, jle32
  , jsgt64, jsgt32, jsge64, jsge32
  , jslt64, jslt32, jsle64, jsle32
  , jset64, jset32
  , ja, ja32

    -- * Control flow
  , exit
  , call
  ) where

import Control.Monad (when, foldM)
import Control.Monad.Trans.State.Strict (State, execState, state, modify')
import Data.Foldable (toList)
import Data.Int (Int16, Int32, Int64)
import qualified Data.Map.Strict as Map
import Data.Sequence (Seq, (|>))
import qualified Data.Sequence as Seq

import GenericInstructions (SourceType)
import qualified Instructions as I
import Types

-- ---------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------

-- | A symbolic jump target. Created with 'newLabel', placed with 'label'.
newtype Label = Label Int deriving (Eq, Ord, Show)

-- | Which instruction field holds the jump offset.
data FixupKind
  = FixupOff  -- ^ _off field (Int16) — conditional jumps, bpf_ja32
  | FixupImm  -- ^ _imm field (Int32) — bpf_ja (BPF_JMP class)
  deriving (Show)

-- | A pending label reference that needs patching after all instructions
-- are emitted and label positions are known.
data Fixup = Fixup
  { _fxSeqIdx :: !Int       -- index into instruction Seq (for Seq.update)
  , _fxPCSlot :: !Int       -- PC slot of the jump instruction (for offset calc)
  , _fxLabel  :: !Label     -- target label
  , _fxKind   :: !FixupKind -- which field to patch
  } deriving (Show)

data BuildState = BuildState
  { _insns   :: !(Seq Instruction)    -- emitted instructions
  , _nextPC  :: !Int                  -- current PC slot (wide insns count as 2)
  , _nextLbl :: !Int                  -- fresh label counter
  , _labels  :: !(Map.Map Label Int)  -- label -> PC slot
  , _fixups  :: ![Fixup]              -- pending jump fixups
  }

-- | The BPF program builder monad.
type BPF a = State BuildState a

initialState :: BuildState
initialState = BuildState
  { _insns   = Seq.empty
  , _nextPC  = 0
  , _nextLbl = 0
  , _labels  = Map.empty
  , _fixups  = []
  }

-- | Number of PC slots an instruction occupies.
-- Standard instructions take 1 slot; wide (128-bit) instructions take 2.
instrSlots :: Instruction -> Int
instrSlots StandardInstruction{}  = 1
instrSlots ExtendedInstruction{} = 2

-- ---------------------------------------------------------------------------
-- Core operations
-- ---------------------------------------------------------------------------

-- | Emit a single instruction into the program.
emit :: Instruction -> BPF ()
emit insn = modify' $ \st ->
  st { _insns  = _insns st |> insn
     , _nextPC = _nextPC st + instrSlots insn
     }

-- | Emit an instruction and return its Seq index and PC slot.
emitIndexed :: Instruction -> BPF (Int, Int)
emitIndexed insn = state $ \st ->
  let idx = Seq.length (_insns st)
      pc  = _nextPC st
  in ( (idx, pc)
     , st { _insns  = _insns st |> insn
          , _nextPC = pc + instrSlots insn
          }
     )

-- | Create a fresh label. Does not define its position — use 'label' for that.
newLabel :: BPF Label
newLabel = state $ \st ->
  ( Label (_nextLbl st)
  , st { _nextLbl = _nextLbl st + 1 }
  )

-- | Define the current PC position as the target for a label.
-- Jumps to this label will land on the next instruction emitted.
label :: Label -> BPF ()
label lbl = modify' $ \st ->
  st { _labels = Map.insert lbl (_nextPC st) (_labels st) }

-- | Register a fixup: the instruction at seqIdx needs its offset field
-- patched once the target label's position is known.
addFixup :: Int -> Int -> Label -> FixupKind -> BPF ()
addFixup idx pc lbl kind = modify' $ \st ->
  st { _fixups = Fixup idx pc lbl kind : _fixups st }

-- ---------------------------------------------------------------------------
-- Assembly: run the monad and resolve labels
-- ---------------------------------------------------------------------------

-- | Run a BPF program builder and produce a list of instructions.
-- Returns 'Left' if any labels are undefined or jump offsets overflow.
assemble :: BPF () -> Either String [Instruction]
assemble prog = resolve (execState prog initialState)

-- | Resolve all label fixups, patching jump offsets.
resolve :: BuildState -> Either String [Instruction]
resolve st = do
  patched <- foldM applyFixup (_insns st) (_fixups st)
  Right (toList patched)
  where
    applyFixup insns (Fixup idx pc lbl kind) = do
      targetPC <- case Map.lookup lbl (_labels st) of
        Just t  -> Right t
        Nothing -> Left ("undefined label: " ++ show lbl)
      let offset = targetPC - (pc + 1)
      case kind of
        FixupOff -> do
          when (offset < fromIntegral (minBound :: Int16) ||
                offset > fromIntegral (maxBound :: Int16)) $
            Left ("jump offset " ++ show offset ++
                  " out of Int16 range for " ++ show lbl)
          let patched = patchOff (fromIntegral offset) (Seq.index insns idx)
          Right (Seq.update idx patched insns)
        FixupImm -> do
          when (offset < fromIntegral (minBound :: Int32) ||
                offset > fromIntegral (maxBound :: Int32)) $
            Left ("jump offset " ++ show offset ++
                  " out of Int32 range for " ++ show lbl)
          let patched = patchImm (fromIntegral offset) (Seq.index insns idx)
          Right (Seq.update idx patched insns)

-- | Patch the _off field of an instruction (used for conditional jumps).
patchOff :: Int16 -> Instruction -> Instruction
patchOff newOff (StandardInstruction op dst src _ imm) =
  StandardInstruction op dst src newOff imm
patchOff newOff (ExtendedInstruction op dst src _ imm res next) =
  ExtendedInstruction op dst src newOff imm res next

-- | Patch the _imm field of an instruction (used for bpf_ja).
patchImm :: Int32 -> Instruction -> Instruction
patchImm newImm (StandardInstruction op dst src off _) =
  StandardInstruction op dst src off newImm
patchImm newImm (ExtendedInstruction op dst src off _ res next) =
  ExtendedInstruction op dst src off newImm res next

-- ---------------------------------------------------------------------------
-- Jump wrappers (with label support)
--
-- These emit a jump instruction with a placeholder offset (0), then register
-- a fixup so 'assemble' can patch in the real offset once all labels are
-- defined.
-- ---------------------------------------------------------------------------

-- | Helper: emit a conditional jump and register a fixup for its label.
emitCondJmp :: (SourceType a)
            => (Reg -> a -> Int16 -> Instruction)
            -> Reg -> a -> Label -> BPF ()
emitCondJmp mkJmp dst src lbl = do
  (idx, pc) <- emitIndexed (mkJmp dst src 0)
  addFixup idx pc lbl FixupOff

jeq64 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jeq64 = emitCondJmp I.bpf_jeq64

jeq32 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jeq32 = emitCondJmp I.bpf_jeq32

jne64 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jne64 = emitCondJmp I.bpf_jne64

jne32 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jne32 = emitCondJmp I.bpf_jne32

jgt64 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jgt64 = emitCondJmp I.bpf_jgt64

jgt32 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jgt32 = emitCondJmp I.bpf_jgt32

jge64 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jge64 = emitCondJmp I.bpf_jge64

jge32 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jge32 = emitCondJmp I.bpf_jge32

jlt64 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jlt64 = emitCondJmp I.bpf_jlt64

jlt32 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jlt32 = emitCondJmp I.bpf_jlt32

jle64 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jle64 = emitCondJmp I.bpf_jle64

jle32 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jle32 = emitCondJmp I.bpf_jle32

jsgt64 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jsgt64 = emitCondJmp I.bpf_jsgt64

jsgt32 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jsgt32 = emitCondJmp I.bpf_jsgt32

jsge64 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jsge64 = emitCondJmp I.bpf_jsge64

jsge32 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jsge32 = emitCondJmp I.bpf_jsge32

jslt64 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jslt64 = emitCondJmp I.bpf_jslt64

jslt32 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jslt32 = emitCondJmp I.bpf_jslt32

jsle64 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jsle64 = emitCondJmp I.bpf_jsle64

jsle32 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jsle32 = emitCondJmp I.bpf_jsle32

jset64 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jset64 = emitCondJmp I.bpf_jset64

jset32 :: (SourceType a) => Reg -> a -> Label -> BPF ()
jset32 = emitCondJmp I.bpf_jset32

-- | Unconditional jump (BPF_JMP class, 32-bit offset in _imm).
ja :: Label -> BPF ()
ja lbl = do
  (idx, pc) <- emitIndexed (I.bpf_ja 0)
  addFixup idx pc lbl FixupImm

-- | Unconditional jump (BPF_JMP32 class, 16-bit offset in _off).
ja32 :: Label -> BPF ()
ja32 lbl = do
  (idx, pc) <- emitIndexed (I.bpf_ja32 0)
  addFixup idx pc lbl FixupOff

-- ---------------------------------------------------------------------------
-- Control flow
-- ---------------------------------------------------------------------------

-- | Terminate the BPF program. R0 holds the return value.
exit :: BPF ()
exit = emit I.bpf_exit

-- | Call a kernel helper function by numeric ID.
-- Arguments must be in R1–R5; return value lands in R0.
call :: Int32 -> BPF ()
call = emit . I.bpf_call

-- ---------------------------------------------------------------------------
-- ALU wrappers
-- ---------------------------------------------------------------------------

add64 :: (SourceType a) => Reg -> a -> BPF ()
add64 dst src = emit $ I.bpf_add64 dst src

add32 :: (SourceType a) => Reg -> a -> BPF ()
add32 dst src = emit $ I.bpf_add32 dst src

sub64 :: (SourceType a) => Reg -> a -> BPF ()
sub64 dst src = emit $ I.bpf_sub64 dst src

sub32 :: (SourceType a) => Reg -> a -> BPF ()
sub32 dst src = emit $ I.bpf_sub32 dst src

mul64 :: (SourceType a) => Reg -> a -> BPF ()
mul64 dst src = emit $ I.bpf_mul64 dst src

mul32 :: (SourceType a) => Reg -> a -> BPF ()
mul32 dst src = emit $ I.bpf_mul32 dst src

div64 :: (SourceType a) => Reg -> a -> BPF ()
div64 dst src = emit $ I.bpf_div64 dst src

div32 :: (SourceType a) => Reg -> a -> BPF ()
div32 dst src = emit $ I.bpf_div32 dst src

sdiv64 :: (SourceType a) => Reg -> a -> BPF ()
sdiv64 dst src = emit $ I.bpf_sdiv64 dst src

sdiv32 :: (SourceType a) => Reg -> a -> BPF ()
sdiv32 dst src = emit $ I.bpf_sdiv32 dst src

mod64 :: (SourceType a) => Reg -> a -> BPF ()
mod64 dst src = emit $ I.bpf_mod64 dst src

mod32 :: (SourceType a) => Reg -> a -> BPF ()
mod32 dst src = emit $ I.bpf_mod32 dst src

smod64 :: (SourceType a) => Reg -> a -> BPF ()
smod64 dst src = emit $ I.bpf_smod64 dst src

smod32 :: (SourceType a) => Reg -> a -> BPF ()
smod32 dst src = emit $ I.bpf_smod32 dst src

or64 :: (SourceType a) => Reg -> a -> BPF ()
or64 dst src = emit $ I.bpf_or64 dst src

or32 :: (SourceType a) => Reg -> a -> BPF ()
or32 dst src = emit $ I.bpf_or32 dst src

and64 :: (SourceType a) => Reg -> a -> BPF ()
and64 dst src = emit $ I.bpf_and64 dst src

and32 :: (SourceType a) => Reg -> a -> BPF ()
and32 dst src = emit $ I.bpf_and32 dst src

xor64 :: (SourceType a) => Reg -> a -> BPF ()
xor64 dst src = emit $ I.bpf_xor64 dst src

xor32 :: (SourceType a) => Reg -> a -> BPF ()
xor32 dst src = emit $ I.bpf_xor32 dst src

lsh64 :: (SourceType a) => Reg -> a -> BPF ()
lsh64 dst src = emit $ I.bpf_lsh64 dst src

lsh32 :: (SourceType a) => Reg -> a -> BPF ()
lsh32 dst src = emit $ I.bpf_lsh32 dst src

rsh64 :: (SourceType a) => Reg -> a -> BPF ()
rsh64 dst src = emit $ I.bpf_rsh64 dst src

rsh32 :: (SourceType a) => Reg -> a -> BPF ()
rsh32 dst src = emit $ I.bpf_rsh32 dst src

arsh64 :: (SourceType a) => Reg -> a -> BPF ()
arsh64 dst src = emit $ I.bpf_arsh64 dst src

arsh32 :: (SourceType a) => Reg -> a -> BPF ()
arsh32 dst src = emit $ I.bpf_arsh32 dst src

neg64 :: Reg -> BPF ()
neg64 = emit . I.bpf_neg64

neg32 :: Reg -> BPF ()
neg32 = emit . I.bpf_neg32

-- ---------------------------------------------------------------------------
-- Move wrappers
-- ---------------------------------------------------------------------------

mov64 :: (SourceType a) => Reg -> a -> BPF ()
mov64 dst src = emit $ I.bpf_mov64 dst src

mov32 :: (SourceType a) => Reg -> a -> BPF ()
mov32 dst src = emit $ I.bpf_mov32 dst src

movSX64 :: Reg -> Reg -> ExtensionSize -> BPF ()
movSX64 dst src size = emit $ I.bpf_movSX64 dst src size

movSX32 :: Reg -> Reg -> ExtensionSize -> BPF ()
movSX32 dst src size = emit $ I.bpf_movSX32 dst src size

-- ---------------------------------------------------------------------------
-- Byte swap wrappers
-- ---------------------------------------------------------------------------

tole :: Reg -> EndianWidth -> BPF ()
tole dst w = emit $ I.bpf_tole dst w

toBe :: Reg -> EndianWidth -> BPF ()
toBe dst w = emit $ I.bpf_toBe dst w

bswap :: Reg -> EndianWidth -> BPF ()
bswap dst w = emit $ I.bpf_bswap dst w

-- ---------------------------------------------------------------------------
-- Load / Store wrappers
-- ---------------------------------------------------------------------------

ldx64 :: Reg -> Reg -> Int16 -> BPF ()
ldx64 dst src off = emit $ I.bpf_ldx64 dst src off

ldx32 :: Reg -> Reg -> Int16 -> BPF ()
ldx32 dst src off = emit $ I.bpf_ldx32 dst src off

ldx16 :: Reg -> Reg -> Int16 -> BPF ()
ldx16 dst src off = emit $ I.bpf_ldx16 dst src off

ldx8 :: Reg -> Reg -> Int16 -> BPF ()
ldx8 dst src off = emit $ I.bpf_ldx8 dst src off

st64 :: Reg -> Int16 -> Int32 -> BPF ()
st64 dst off imm = emit $ I.bpf_st64 dst off imm

st32 :: Reg -> Int16 -> Int32 -> BPF ()
st32 dst off imm = emit $ I.bpf_st32 dst off imm

st16 :: Reg -> Int16 -> Int32 -> BPF ()
st16 dst off imm = emit $ I.bpf_st16 dst off imm

st8 :: Reg -> Int16 -> Int32 -> BPF ()
st8 dst off imm = emit $ I.bpf_st8 dst off imm

stx64 :: Reg -> Reg -> Int16 -> BPF ()
stx64 dst src off = emit $ I.bpf_stx64 dst src off

stx32 :: Reg -> Reg -> Int16 -> BPF ()
stx32 dst src off = emit $ I.bpf_stx32 dst src off

stx16 :: Reg -> Reg -> Int16 -> BPF ()
stx16 dst src off = emit $ I.bpf_stx16 dst src off

stx8 :: Reg -> Reg -> Int16 -> BPF ()
stx8 dst src off = emit $ I.bpf_stx8 dst src off

-- | Load a 64-bit immediate (wide instruction, occupies 2 PC slots).
ldImm64 :: Reg -> Int64 -> BPF ()
ldImm64 dst val = emit $ I.bpf_ld_imm64 dst val

-- ---------------------------------------------------------------------------
-- Atomic wrappers
-- ---------------------------------------------------------------------------

atomicAdd64 :: Reg -> Reg -> Int16 -> BPF ()
atomicAdd64 dst src off = emit $ I.bpf_atomic_add64 dst src off

atomicAdd32 :: Reg -> Reg -> Int16 -> BPF ()
atomicAdd32 dst src off = emit $ I.bpf_atomic_add32 dst src off

atomicOr64 :: Reg -> Reg -> Int16 -> BPF ()
atomicOr64 dst src off = emit $ I.bpf_atomic_or64 dst src off

atomicOr32 :: Reg -> Reg -> Int16 -> BPF ()
atomicOr32 dst src off = emit $ I.bpf_atomic_or32 dst src off

atomicAnd64 :: Reg -> Reg -> Int16 -> BPF ()
atomicAnd64 dst src off = emit $ I.bpf_atomic_and64 dst src off

atomicAnd32 :: Reg -> Reg -> Int16 -> BPF ()
atomicAnd32 dst src off = emit $ I.bpf_atomic_and32 dst src off

atomicXor64 :: Reg -> Reg -> Int16 -> BPF ()
atomicXor64 dst src off = emit $ I.bpf_atomic_xor64 dst src off

atomicXor32 :: Reg -> Reg -> Int16 -> BPF ()
atomicXor32 dst src off = emit $ I.bpf_atomic_xor32 dst src off

atomicFetchAdd64 :: Reg -> Reg -> Int16 -> BPF ()
atomicFetchAdd64 dst src off = emit $ I.bpf_atomic_fetch_add64 dst src off

atomicFetchAdd32 :: Reg -> Reg -> Int16 -> BPF ()
atomicFetchAdd32 dst src off = emit $ I.bpf_atomic_fetch_add32 dst src off

atomicFetchOr64 :: Reg -> Reg -> Int16 -> BPF ()
atomicFetchOr64 dst src off = emit $ I.bpf_atomic_fetch_or64 dst src off

atomicFetchOr32 :: Reg -> Reg -> Int16 -> BPF ()
atomicFetchOr32 dst src off = emit $ I.bpf_atomic_fetch_or32 dst src off

atomicFetchAnd64 :: Reg -> Reg -> Int16 -> BPF ()
atomicFetchAnd64 dst src off = emit $ I.bpf_atomic_fetch_and64 dst src off

atomicFetchAnd32 :: Reg -> Reg -> Int16 -> BPF ()
atomicFetchAnd32 dst src off = emit $ I.bpf_atomic_fetch_and32 dst src off

atomicFetchXor64 :: Reg -> Reg -> Int16 -> BPF ()
atomicFetchXor64 dst src off = emit $ I.bpf_atomic_fetch_xor64 dst src off

atomicFetchXor32 :: Reg -> Reg -> Int16 -> BPF ()
atomicFetchXor32 dst src off = emit $ I.bpf_atomic_fetch_xor32 dst src off

atomicXchg64 :: Reg -> Reg -> Int16 -> BPF ()
atomicXchg64 dst src off = emit $ I.bpf_atomic_xchg64 dst src off

atomicXchg32 :: Reg -> Reg -> Int16 -> BPF ()
atomicXchg32 dst src off = emit $ I.bpf_atomic_xchg32 dst src off

atomicCmpxchg64 :: Reg -> Reg -> Int16 -> BPF ()
atomicCmpxchg64 dst src off = emit $ I.bpf_atomic_cmpxchg64 dst src off

atomicCmpxchg32 :: Reg -> Reg -> Int16 -> BPF ()
atomicCmpxchg32 dst src off = emit $ I.bpf_atomic_cmpxchg32 dst src off
