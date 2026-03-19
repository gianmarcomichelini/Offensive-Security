#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win(int arg1, int arg2) {
    if (arg1 == 0xdeadbeef && arg2 == 0xcafebabe) {
        puts("Door unlocked!");
        system("/bin/sh");
    } else {
        printf("Wrong keys: 0x%x, 0x%x\n", arg1, arg2);
    }
}

void gadgets() {
    __asm__("pop %rdi; ret");
    __asm__("pop %rsi; ret");
}

void vuln() {
    char buffer[64];
    puts("Welcome to the tiny escape room!");
    puts("Two magic keys open the door.");
    puts("keys?");
    gets(buffer);
}

int main() {
    setup();
    vuln();
    return 0;
}
