#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    puts("How did you fit through that tiny window?!");
    system("/bin/sh");
}

void vuln() {
    char whisper[16];

    puts("Psst! This is the whispering wall.");
    puts("Only tiny messages allowed... or are they?");
    puts("whisper:");

    gets(whisper);
}

int main() {
    setup();
    vuln();
    return 0;
}
