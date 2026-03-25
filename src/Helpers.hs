{- HLINT ignore "Use camelCase" -}
module Helpers where

-- BPF helper function wrappers.
--
-- Each function emits a single BPF_CALL instruction with the helper's numeric
-- ID in the imm field.  Arguments must be placed in R1–R5 before the call;
-- the return value lands in R0.  R1–R5 are clobbered after the call.
--
-- Helper IDs are stable and match the kernel's bpf_func_id enum
-- (include/uapi/linux/bpf.h).  Grouped by category below.

import Data.Int (Int32)
import Instructions (bpf_call)
import Types (Instruction)

-- | Helper function ID — an alias for documentation clarity.
type HelperID = Int32

-- ---------------------------------------------------------------------------
-- Map operations
--
-- These are the core helpers for interacting with BPF maps.
-- Arguments (R1–R4) must be set up by the caller before calling.
--
-- Typical usage (bpf_map_lookup_elem):
--   R1 = pointer to map (loaded via bpf_ld_imm64 with map FD)
--   R2 = pointer to key on stack
--   Returns: R0 = pointer to value, or 0 (NULL) if not found
-- ---------------------------------------------------------------------------

helper_map_lookup_elem_id :: HelperID
helper_map_lookup_elem_id = 1

-- | Look up a key in a BPF map.
--   R1 = map pointer, R2 = key pointer.
--   Returns pointer to value in R0, or 0 if not found.
helper_map_lookup_elem :: Instruction
helper_map_lookup_elem = bpf_call helper_map_lookup_elem_id

helper_map_update_elem_id :: HelperID
helper_map_update_elem_id = 2

-- | Insert or update a key-value pair in a BPF map.
--   R1 = map pointer, R2 = key pointer, R3 = value pointer, R4 = flags.
--   Returns 0 on success, negative error code on failure.
helper_map_update_elem :: Instruction
helper_map_update_elem = bpf_call helper_map_update_elem_id

helper_map_delete_elem_id :: HelperID
helper_map_delete_elem_id = 3

-- | Delete a key from a BPF map.
--   R1 = map pointer, R2 = key pointer.
--   Returns 0 on success, negative error code on failure.
helper_map_delete_elem :: Instruction
helper_map_delete_elem = bpf_call helper_map_delete_elem_id

-- ---------------------------------------------------------------------------
-- Memory access
-- ---------------------------------------------------------------------------

helper_probe_read_id :: HelperID
helper_probe_read_id = 4

-- | Safely read from kernel memory into a BPF stack buffer.
--   R1 = destination pointer, R2 = size, R3 = unsafe source pointer.
--   Returns 0 on success.
helper_probe_read :: Instruction
helper_probe_read = bpf_call helper_probe_read_id

helper_probe_read_str_id :: HelperID
helper_probe_read_str_id = 45

-- | Read a NUL-terminated string from kernel memory.
--   R1 = destination pointer, R2 = max size, R3 = unsafe source pointer.
--   Returns number of bytes read (including NUL), or negative error.
helper_probe_read_str :: Instruction
helper_probe_read_str = bpf_call helper_probe_read_str_id

helper_probe_read_user_str_id :: HelperID
helper_probe_read_user_str_id = 114

-- | Read a NUL-terminated string from user-space memory.
--   R1 = destination pointer, R2 = max size, R3 = unsafe user pointer.
--   Returns number of bytes read (including NUL), or negative error.
helper_probe_read_user_str :: Instruction
helper_probe_read_user_str = bpf_call helper_probe_read_user_str_id

-- ---------------------------------------------------------------------------
-- Time
-- ---------------------------------------------------------------------------

helper_ktime_get_ns_id :: HelperID
helper_ktime_get_ns_id = 5

-- | Get monotonic clock time in nanoseconds.
--   No arguments.
--   Returns nanoseconds in R0.
helper_ktime_get_ns :: Instruction
helper_ktime_get_ns = bpf_call helper_ktime_get_ns_id

-- ---------------------------------------------------------------------------
-- Tracing / debugging
-- ---------------------------------------------------------------------------

helper_trace_printk_id :: HelperID
helper_trace_printk_id = 6

-- | Printf-style debug output to /sys/kernel/debug/tracing/trace_pipe.
--   R1 = format string pointer, R2 = format string size,
--   R3–R5 = format arguments.
--   Returns number of bytes written, or negative error.
helper_trace_printk :: Instruction
helper_trace_printk = bpf_call helper_trace_printk_id

-- ---------------------------------------------------------------------------
-- Random
-- ---------------------------------------------------------------------------

helper_get_prandom_u32_id :: HelperID
helper_get_prandom_u32_id = 7

-- | Get a pseudo-random 32-bit number.
--   No arguments.
--   Returns random u32 in R0.
helper_get_prandom_u32 :: Instruction
helper_get_prandom_u32 = bpf_call helper_get_prandom_u32_id

-- ---------------------------------------------------------------------------
-- Socket / skb operations
-- ---------------------------------------------------------------------------

helper_skb_store_bytes_id :: HelperID
helper_skb_store_bytes_id = 9

-- | Store bytes into a packet (sk_buff).
--   R1 = skb, R2 = offset, R3 = source pointer, R4 = length, R5 = flags.
--   Returns 0 on success.
helper_skb_store_bytes :: Instruction
helper_skb_store_bytes = bpf_call helper_skb_store_bytes_id

helper_skb_load_bytes_id :: HelperID
helper_skb_load_bytes_id = 26

-- | Load bytes from a packet (sk_buff) into a buffer.
--   R1 = skb, R2 = offset, R3 = dest pointer, R4 = length.
--   Returns 0 on success.
helper_skb_load_bytes :: Instruction
helper_skb_load_bytes = bpf_call helper_skb_load_bytes_id

-- ---------------------------------------------------------------------------
-- Networking — redirect (XDP / TC)
-- ---------------------------------------------------------------------------

helper_redirect_id :: HelperID
helper_redirect_id = 51

-- | Redirect a packet to another network interface (XDP/TC).
--   R1 = ifindex, R2 = flags.
--   Returns XDP_REDIRECT on success.
helper_redirect :: Instruction
helper_redirect = bpf_call helper_redirect_id

helper_redirect_map_id :: HelperID
helper_redirect_map_id = 61

-- | Redirect a packet via a DEVMAP/CPUMAP.
--   R1 = map pointer, R2 = key, R3 = flags.
--   Returns XDP_REDIRECT on success.
helper_redirect_map :: Instruction
helper_redirect_map = bpf_call helper_redirect_map_id

-- ---------------------------------------------------------------------------
-- Perf events
-- ---------------------------------------------------------------------------

helper_perf_event_output_id :: HelperID
helper_perf_event_output_id = 25

-- | Write data to a perf event ring buffer (BPF_MAP_TYPE_PERF_EVENT_ARRAY).
--   R1 = ctx, R2 = map pointer, R3 = flags, R4 = data pointer, R5 = data size.
--   Returns 0 on success.
helper_perf_event_output :: Instruction
helper_perf_event_output = bpf_call helper_perf_event_output_id

-- ---------------------------------------------------------------------------
-- Cgroup / socket helpers
-- ---------------------------------------------------------------------------

helper_get_current_pid_tgid_id :: HelperID
helper_get_current_pid_tgid_id = 14

-- | Get the current PID and TGID (thread group ID).
--   No arguments.
--   Returns (tgid << 32 | pid) in R0.
helper_get_current_pid_tgid :: Instruction
helper_get_current_pid_tgid = bpf_call helper_get_current_pid_tgid_id

helper_get_current_uid_gid_id :: HelperID
helper_get_current_uid_gid_id = 15

-- | Get the current UID and GID.
--   No arguments.
--   Returns (gid << 32 | uid) in R0.
helper_get_current_uid_gid :: Instruction
helper_get_current_uid_gid = bpf_call helper_get_current_uid_gid_id

helper_get_current_comm_id :: HelperID
helper_get_current_comm_id = 16

-- | Get the current process name (comm).
--   R1 = buffer pointer, R2 = buffer size.
--   Returns 0 on success.
helper_get_current_comm :: Instruction
helper_get_current_comm = bpf_call helper_get_current_comm_id

-- ---------------------------------------------------------------------------
-- Ring buffer (modern replacement for perf event arrays)
-- ---------------------------------------------------------------------------

helper_ringbuf_output_id :: HelperID
helper_ringbuf_output_id = 130

-- | Write data to a BPF ring buffer (BPF_MAP_TYPE_RINGBUF).
--   R1 = ringbuf map pointer, R2 = data pointer, R3 = data size, R4 = flags.
--   Returns 0 on success.
helper_ringbuf_output :: Instruction
helper_ringbuf_output = bpf_call helper_ringbuf_output_id

helper_ringbuf_reserve_id :: HelperID
helper_ringbuf_reserve_id = 131

-- | Reserve space in a ring buffer for writing.
--   R1 = ringbuf map pointer, R2 = data size, R3 = flags.
--   Returns pointer to reserved memory in R0, or 0 on failure.
helper_ringbuf_reserve :: Instruction
helper_ringbuf_reserve = bpf_call helper_ringbuf_reserve_id

helper_ringbuf_submit_id :: HelperID
helper_ringbuf_submit_id = 132

-- | Submit a previously reserved ring buffer entry.
--   R1 = reserved data pointer (from ringbuf_reserve), R2 = flags.
helper_ringbuf_submit :: Instruction
helper_ringbuf_submit = bpf_call helper_ringbuf_submit_id

helper_ringbuf_discard_id :: HelperID
helper_ringbuf_discard_id = 133

-- | Discard a previously reserved ring buffer entry.
--   R1 = reserved data pointer, R2 = flags.
helper_ringbuf_discard :: Instruction
helper_ringbuf_discard = bpf_call helper_ringbuf_discard_id
