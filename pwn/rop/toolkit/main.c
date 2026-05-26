#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

__attribute__((naked, used)) void pop_rdi_ret(void) { __asm__("pop %rdi; ret"); }
__attribute__((naked, used)) void pop_rsi_ret(void) { __asm__("pop %rsi; ret"); }
__attribute__((naked, used)) void pop_rdx_ret(void) { __asm__("pop %rdx; ret"); }
__attribute__((naked, used)) void ret_gadget(void)  { __asm__("ret"); }


__attribute__((noinline))
static void win(uint64_t a, uint64_t b, uint64_t c) {
    if (a != 0x1111111111111111ULL) { _exit(1); }
    if (b != 0x2222222222222222ULL) { _exit(2); }
    if (c != 0x3333333333333333ULL) { _exit(3); }

    volatile char path[8];
    path[0] = '/'; path[1] = 'b'; path[2] = 'i'; path[3] = 'n';
    path[4] = '/'; path[5] = 's'; path[6] = 'h'; path[7] = '\0';

    long r;
    __asm__ volatile (
        "mov $59, %%rax\n"
        "xor %%rsi, %%rsi\n"
        "xor %%rdx, %%rdx\n"
        "syscall\n"
        : "=a"(r) : "D"(path) : "rcx", "r11", "memory"
    );
}

static void vuln(void) {
    char buf[64];

    printf("[toolkit] Input: ");
    (void)read(STDIN_FILENO, buf, 256);
}

int main(void) {
    setup();
    vuln();
    return 0;
}
