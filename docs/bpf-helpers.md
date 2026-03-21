# BPF Helper Functions

## What are BPF helpers?

BPF helper functions are kernel-provided functions that eBPF programs can call
to interact with the kernel and the outside world.  An eBPF program runs in a
sandboxed environment — it cannot call arbitrary kernel functions.  Instead, the
kernel exposes a fixed set of helper functions, each identified by a numeric ID.

When a BPF program needs to perform an action beyond pure register arithmetic
(look up a map, get the current time, print a debug message, redirect a packet),
it calls a helper function.

## How helper calls work

At the instruction level, calling a helper is a single `BPF_CALL` instruction:

```
opcode = BPF_JMP | BPF_CALL | BPF_K   (0x85)
imm    = helper function ID
```

The calling convention mirrors a C function call:

| Step       | Detail                                           |
|------------|--------------------------------------------------|
| Arguments  | R1–R5 hold up to 5 arguments (left to right)    |
| Call       | `bpf_call <helper_id>`                            |
| Return     | R0 holds the return value                        |
| Clobbered  | R1–R5 are caller-saved (destroyed after call)    |
| Preserved  | R6–R9 are callee-saved (survive the call)        |

The kernel verifier checks at load time that:
- The helper ID is valid for the program type
- The argument types match what the helper expects
- Pointer arguments point to valid memory regions

## Helper function IDs

Helper IDs are defined in the kernel source at `include/uapi/linux/bpf.h` in the
`bpf_func_id` enum.  The numbering is stable — IDs are never reused or
renumbered.  New helpers are added at the end.

Below are the most commonly used helpers.  The full list contains 200+ helpers
as of kernel 6.x.

### Map operations

These are the fundamental helpers for interacting with BPF maps (key-value
stores shared between BPF programs and userspace):

| ID | Name                      | Signature (C)                                  | Description                           |
|----|---------------------------|-------------------------------------------------|---------------------------------------|
| 1  | `bpf_map_lookup_elem`     | `void *map, void *key -> void *value`           | Look up key, returns pointer or NULL  |
| 2  | `bpf_map_update_elem`     | `void *map, void *key, void *value, u64 flags`  | Insert or update key-value pair       |
| 3  | `bpf_map_delete_elem`     | `void *map, void *key -> int`                   | Delete key from map                   |

### Tracing / debugging

| ID | Name                      | Signature (C)                                  | Description                           |
|----|---------------------------|-------------------------------------------------|---------------------------------------|
| 6  | `bpf_trace_printk`        | `fmt, fmt_size, arg1, arg2, arg3 -> int`        | Printf to `/sys/kernel/debug/tracing/trace_pipe` |

### Time

| ID | Name                      | Signature (C)                                  | Description                           |
|----|---------------------------|-------------------------------------------------|---------------------------------------|
| 5  | `bpf_ktime_get_ns`        | `void -> u64`                                   | Monotonic clock in nanoseconds        |

### Networking (XDP / TC)

| ID | Name                      | Signature (C)                                  | Description                           |
|----|---------------------------|-------------------------------------------------|---------------------------------------|
| 51 | `bpf_redirect`            | `ifindex, flags -> int`                         | Redirect packet to another interface  |
| 61 | `bpf_redirect_map`        | `void *map, u32 key, u64 flags -> int`          | Redirect via BPF_MAP_TYPE_DEVMAP      |

### Random

| ID | Name                      | Signature (C)                                  | Description                           |
|----|---------------------------|-------------------------------------------------|---------------------------------------|
| 7  | `bpf_get_prandom_u32`     | `void -> u32`                                   | Pseudo-random 32-bit number           |

### Packet access (XDP / TC)

| ID | Name                      | Signature (C)                                  | Description                           |
|----|---------------------------|-------------------------------------------------|---------------------------------------|
| 4  | `bpf_probe_read`          | `void *dst, u32 size, void *unsafe_ptr -> int`  | Safe read from kernel memory          |
| 45 | `bpf_probe_read_str`      | `void *dst, u32 size, void *unsafe_ptr -> int`  | Read string from kernel memory        |

## How hbpf exposes helpers

The `Helpers` module (`src/Helpers.hs`) provides **typed symbolic wrappers** —
one Haskell function per helper — so that:

1. Users don't need to memorize numeric IDs
2. The function name documents what the helper does
3. Future work can validate argument setup at the type level

### Example usage

```haskell
-- Without typed helpers (raw ID):
program = [ bpf_mov64 R1 (6 :: Int)    -- helper ID for bpf_trace_printk
           , bpf_call 6
           ]

-- With typed helpers (symbolic name):
program = [ ...                         -- set up R1-R5 with arguments
           , helper_trace_printk        -- emits bpf_call 6
           ]
```

### Design: the Helpers module

The `Helpers` module (`src/Helpers.hs`) defines:

1. A `HelperID` type alias (`Int32`) for documentation
2. Named constants for each helper function ID
3. Convenience instruction builders that emit `bpf_call <id>`

The helpers are grouped by category (map ops, tracing, networking, etc.)
following the kernel's grouping.

## Program type restrictions

Not all helpers are available to all program types.  For example:
- `bpf_redirect` is only available to XDP and TC programs
- `bpf_trace_printk` is available to most program types but not all
- `bpf_map_lookup_elem` is available to all program types

The kernel verifier enforces these restrictions at load time.  For now, hbpf
does not enforce program-type restrictions at compile time — all helpers are
available regardless of target program type.  This is a future enhancement
tracked in the TODO.

## References

- Kernel source: `include/uapi/linux/bpf.h` — canonical `bpf_func_id` enum
- Man page: `bpf-helpers(7)` — documents each helper's signature and semantics
- [Cilium BPF reference](https://docs.cilium.io/en/latest/bpf/) — excellent overview
