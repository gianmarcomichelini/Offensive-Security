#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    printf("Mission accomplished! Opening airlock:\n");
    system("/bin/sh");
}

void vuln() {
    char buf[64];
    
    printf("Enter your astronaut ID: ");
    read(0, buf, 63);
    buf[63] = '\0';
    printf(buf);
    
    printf("\nSubmit your mission log: ");
    read(0, buf, 256);
}

int main() {
    setup();
    printf("Welcome aboard the Space Station!\n");
    vuln();
    return 0;
}
