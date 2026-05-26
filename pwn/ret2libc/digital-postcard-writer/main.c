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
    char buffer[128];
    printf("Design your dream postcard!\n");
    printf("Write your message:\n");
    read(0, buffer, 512);
    printf("Postcard sent!\n");
}

int main() {
    setup();
    puts("Welcome to the Digital Postcard Writer!");
    vuln();
    return 0;
}
