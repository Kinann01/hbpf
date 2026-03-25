import Program
import Types

-- eBPF program for tracing execve() system calls
-- Prints the pid, the command and the executable file. 

handleExecve :: BPF ()
handleExecve = do
  mov64 R9 R1 -- Move the ctx value stored in R1 to R9 because by convension the ctx goes to R1 but R1 is a callee register for helpers 
  bpfGetCurrentPidTgid -- Call bpf_get_current_pid_tgid helper to get the current pid-tgid (store as a whole 64 bit value)
  rsh64 R0 (32 :: Int) -- the return value of the helper is stored in R0 but we are only interested in the pid which is the upper 32 bits
  mov64 R6 R0 -- move the pid value to R6 for later use

  -- stack [-16 ... 0]
  mov64 R1 R10 -- move the frame pointer to R1 to use ths stack for storing the command name
  add64 R1 (-16 :: Int) -- move the stack pointer down by 16 bytes to make space for storing the filename pointer
  mov64 R2 (16 :: Int) -- set the size of the buffer to read the filename (16 bytes)
  bpfGetCurrentComm -- call bpf_get_current_comm helper to ge the command

  -- stack [-80 ... -16]
  mov64 R1 R10 -- move the frame pointer to R1 to use the stack for storing the filename
  add64 R1 (-80 :: Int) -- move the stack pointer down by 64 bytes to make space for storing the filename
  mov64 R2 (64 :: Int) -- set the size of the buffer to read the filename (64 bytes)
  ldx64 R3 R9 16 -- load the filename pointer from the ctx (offset 16) to R3
  bpfProbeReadUserStr -- call bpf_probe_read helper to read the filename from user space

  -- so at this point, we basically have what we need for this trace stored on the stack and in R6
  -- R6 contains the PID
  -- stack [-16 ... 0] contains the command name
  -- stack [-80 ... -16] contains the filename

  -- The hard part would be the formating. In C, the compiler places the formatting in a RO data section and passes a pointer to it. Here we 
  -- do not have a data section. We are basically formatting the string on the stack ourselves. 

  -- Assuming we want to call bpf_printk(%d %s %s\n, pid, comm, filename)
  -- We need to store on the stack the correct format.

  -- Note we have up to -80 already allocated. %d %s %s\n is 10 bytes long (including the null terminator) but we cannot store it at -90 
  -- becuase this will break ABI, so we start from 96 and pad the rest with zeros

  -- "%d %s %s\n\0" in little-endian 32-bit words:
  -- bytes: 25 64 20 25 | 73 20 25 73 | 0a 00 00 00
  st32 R10 (-96) 0x25206425   -- "%d %"
  st32 R10 (-92) 0x73252073   -- "s %s"
  st32 R10 (-88) 0x0000000a   -- "\n\0" (st32 writes 4 bytes, zero pad the rest)

  mov64 R1 R10 -- move the frame pointer to R1 to use the stack for storing the format string
  add64 R1 (-96 :: Int) -- move the stack pointer down by 96
  mov64 R2 (10 :: Int) -- set the size of the format string to 10 bytes

  mov64 R3 R6 -- move the pid value to R3 to pass as the first argument to bpf_printk
  mov64 R4 R10 -- move the frame pointer to R4 to pass the command
  add64 R4 (-16 :: Int) -- move the pointer to the command name to R4
  mov64 R5 R10 -- move the frame pointer to R5 to pass the filename
  add64 R5 (-80 :: Int) -- move the pointer to the filename to R

  -- R1...R5 are now all corectly set up for the bpf_printk helper
  bpfPrintk -- call bpf_printk helper to print the log
  -- Output will go to /sys/kernel/debug/tracing/trace_pipe

  mov64 R0 (0 :: Int) -- return 0 to indicate success
  exit -- exit the program