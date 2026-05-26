#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void vuln() {
    volatile int target = 0;
    char buffer[64];

    puts("Welcome to the lemonade stand!");
    puts("Set today's special price to 0x1337.");
    printf("current price tag: 0x%x\n", target);
    printf("price:");
    
    scanf("%s", buffer);

    if (target == 0x1337) {
        puts("Perfect, that's the special price!");
        system("/bin/sh");
    } else {
        printf("now it's: 0x%x. Try again!\n", target);
    }
}

int main() {
    setup();
    vuln();
    return 0;
}
