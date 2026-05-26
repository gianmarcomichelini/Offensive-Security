#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void vuln(void) {
    char name[64];
    char feedback[64];

    puts("=== Feedback Portal ===");
    puts("Please enter your name:");

    if (!fgets(name, sizeof(name), stdin))
        exit(1);

    printf("Hello, ");
    printf(name);              

    puts("\nNow leave your feedback:");

    read(STDIN_FILENO, feedback, 256);  
}

int main(void) {
    setup();
    vuln();
    return 0;
}
