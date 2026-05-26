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

__attribute__((naked, used))
void _fini_array_entry(void) {
    __asm__(
        "pop %rdi\n"
        "ret\n"
        "pop %rsi\n"
        "ret\n"
    );
}


__attribute__((noinline))
void win(unsigned long code1, unsigned long code2) {
    if (code1 != 0xc0ffeeULL) {
        printf("[chain-reactor] Wrong code 1: 0x%lx\n", code1);
        _exit(1);
    }
    if (code2 != 0xbadc0deULL) {
        printf("[chain-reactor] Wrong code 2: 0x%lx\n", code2);
        _exit(2);
    }

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

    printf("[chain-reactor] Enter activation codes: ");
    (void)read(STDIN_FILENO, buf, 256);
}

int main(void) {
    setup();
    printf("[chain-reactor] Reactor core priming.\n");
    vuln();
    return 0;
}
