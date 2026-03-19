#include <stdio.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void vuln(void) {
    char buf[128];

    printf("secret: %p\n", (void *)buf);
    puts("secret:");

    (void)read(STDIN_FILENO, buf, 1024);

    puts("bye!");
}

int main(void) {
    setup();
    vuln();
    return 0;
}
