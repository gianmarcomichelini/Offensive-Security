#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    puts("Achievement unlocked: unexpected function call!");
    system("/bin/sh");
}

void lose() {
    puts("Nothing special happens.");
}

void vuln() {
    void (*func_ptr)() = lose;
    char buffer[64];

    puts("Mini-game: choose what happens next.");
    puts("go?");
    
    scanf("%s", buffer);

    if (func_ptr) {
        func_ptr();
    }
}

int main() {
    setup();
    vuln();
    return 0;
}
