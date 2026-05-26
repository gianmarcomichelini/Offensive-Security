#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

__attribute__((naked)) void pop_rdi_ret(void) {
    __asm__("pop %rdi; ret");
}

void vuln() {
    char buffer[64];
    puts("The stars know your destiny...");
    printf("Tell me your wish: ");
    gets(buffer);
    puts("The stars have spoken!");
}

int main() {
    setup();
    puts("Welcome to the Digital Fortune Teller!");
    vuln();
    return 0;
}
