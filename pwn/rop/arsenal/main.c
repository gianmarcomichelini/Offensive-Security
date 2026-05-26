#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

char armory[256];

__attribute__((naked, used)) void pop_rdi_ret(void) { __asm__("pop %rdi; ret"); }
__attribute__((naked, used)) void pop_rsi_ret(void) { __asm__("pop %rsi; ret"); }
__attribute__((naked, used)) void pop_rdx_ret(void) { __asm__("pop %rdx; ret"); }
__attribute__((naked, used)) void pop_rax_ret(void) { __asm__("pop %rax; ret"); }
__attribute__((naked, used)) void syscall_ret(void) { __asm__("syscall; ret"); }
__attribute__((naked, used)) void ret_gadget(void)  { __asm__("ret"); }

static void vuln(void) {
    char buf[64];

    puts("[arsenal] The armory is open -- pick your weapons:");
    (void)read(STDIN_FILENO, buf, 512);
    puts("[arsenal] Closing time.");
}

int main(void) {
    setup();
    vuln();
    return 0;
}
