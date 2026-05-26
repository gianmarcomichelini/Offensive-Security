#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void setup_stdio(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

__attribute__((used))
void win(void) {
    system("/bin/sh");
}

__attribute__((noinline))
void vuln(void) {
    char buf[128];
    puts("Enter your signal log entry: ");
    read(STDIN_FILENO, buf, 0x200);
}

__attribute__((noinline))
void handle_client(int fd) {
    FILE *f = fdopen(fd, "r+");
    if (!f) die("fdopen");
    dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);

    setup_stdio();
    puts("=== Lighthouse Control Panel ===");
    puts("1) Record signal log");
    puts("2) Disconnect");
    printf("> ");
    char choice[8];
    if (!fgets(choice, sizeof choice, f)) return;
    switch (choice[0]) {
        case '1':
            vuln();
            puts("Log entry recorded. Over and out.");
            return;
        case '2':
            puts("Disconnecting. Fair winds.");
            return;
        default:
            puts("Unknown command. Disconnecting.");
            break;
    }
}

static void reap(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    setup_stdio();

    signal(SIGCHLD, reap);

    int port = 9001;
    const char *env_port = getenv("PORT");
    if (env_port) port = atoi(env_port);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) die("socket");
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(s, 16) < 0) die("listen");

    printf("[*] Lighthouse beacon active on port %d\n", port);
    for (;;) {
        struct sockaddr_in cli; socklen_t cl = sizeof cli;
        int c = accept(s, (struct sockaddr *)&cli, &cl);
        if (c < 0) {
            if (errno == EINTR) continue;
            die("accept");
        }
        pid_t pid = fork();
        if (pid < 0) die("fork");
        if (pid == 0) {
            // Child
            close(s);
            handle_client(c);
            close(c);
            _exit(0);
        }
        close(c);
    }
}
