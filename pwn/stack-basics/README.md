# Stack Basics

Foundational stack exploitation. No mitigations need to be bypassed — the focus is on understanding the stack frame layout, overflow mechanics, and the control-flow primitives that underpin every subsequent technique.

All binaries in this category have: **no stack canary, NX enabled, PIE disabled**. All addresses are static and predictable on every run.

## Challenges

| challenge | technique | key detail |
|---|---|---|
| [guestbook](guestbook/) | ret2win | gets() into 64-byte buf; 72-byte offset to RIP; ret gadget required for stack alignment |
| [whispering-wall](whispering-wall/) | ret2win | gets() into 16-byte buf; 24-byte offset to RIP; ret gadget for alignment |
| [escape-room](escape-room/) | ret2win + ROP argument setup | pop rdi / pop rsi gadgets set arg1=0xdeadbeef and arg2=0xcafebabe before jumping to win() |
| [lemonade-stand](lemonade-stand/) | single variable overwrite | scanf overflow reaches volatile int target at offset 76; overwrite with p32(0x1337) |
| [cosmic-burger](cosmic-burger/) | multi-variable overwrite | cheese at offset 40 and sauce at offset 44 must both be set in one payload |
| [mini-game](mini-game/) | function pointer overwrite | func_ptr declared after buf[64] on the stack; overflow replaces it with p64(win()) |
| [enchanted-forest](enchanted-forest/) | struct function pointer overwrite | struct { char incantation[64]; void(*cast)(); }; read() overwrites cast at struct offset 64 |
| [cafe-menu](cafe-menu/) | loop index corruption | struct idx at offset 48 overwritten to 71 so the next write lands on saved RIP, skipping the canary slot |

## Core Concepts

**Standard x86-64 frame layout inside a vulnerable function:**

```
[ buf[N]       ]  ← overflow starts here
[ saved RBP    ]  ← 8 bytes of frame pointer
[ saved RIP    ]  ← target: overwrite with win() address
```

**Offset to RIP = buffer size + 8** (for saved RBP). Measure it with a cyclic pattern in pwndbg:
```
pwndbg> cyclic 200
pwndbg> run          # feed cyclic to the binary
pwndbg> cyclic -l <rsp-value>
```

**Stack alignment:** `system()` requires RSP to be 16-byte aligned at the point of a `call`. Insert a bare `ret` gadget before the target address whenever calling `system()`.

**Toolchain:**
- `checksec --file ./binary` — confirm protections
- `nm ./binary | grep win` — static address of win() (PIE off)
- `ROPgadget --binary ./binary | grep ": ret$"` — alignment gadget
