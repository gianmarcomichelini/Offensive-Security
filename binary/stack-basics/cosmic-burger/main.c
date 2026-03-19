#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void vuln() {
    volatile int sauce = 0;
    volatile int cheese = 0;
    char order[32];

    puts("Welcome to the Cosmic Burger Joint!");
    puts("We need the secret sauce (0xBEEF) and the magic cheese (0xF00D).");
    printf("sauce: 0x%x | cheese: 0x%x\n", sauce, cheese);
    puts("What's your order?");

    gets(order);

    printf("sauce: 0x%x | cheese: 0x%x\n", sauce, cheese);

    if (sauce == 0xBEEF && cheese == 0xF00D) {
        puts("The cosmic burger is ready! Here's your reward:");
        system("/bin/sh");
    } else {
        puts("That's not the right combo. Try again!");
    }
}

int main() {
    setup();
    vuln();
    return 0;
}
