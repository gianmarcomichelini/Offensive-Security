#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    printf("You've discovered the forbidden section!\n");
    system("/bin/sh");
}

void vuln() {
    char buf[128];
    
    printf("Sign the guestbook: ");
    read(0, buf, 127);
    buf[127] = '\0';
    printf("Hello, ");
    printf(buf);
    
    printf("\nLeave a review: ");
    read(0, buf, 512);
}

int main() {
    setup();
    printf("Welcome to the Secret Library!\n");
    vuln();
    return 0;
}
