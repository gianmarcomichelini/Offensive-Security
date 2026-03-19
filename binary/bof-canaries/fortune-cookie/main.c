#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void reap_children(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

__attribute__((noreturn)) static void win(void) {
    puts("The stars have aligned! Here's your fortune:");
    char *argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);
    _exit(0);
}

static void read_data(int fd) {
    char buf[64];

    ssize_t n = read(fd, buf, 256);
    if (n <= 0) {
        return;
    }
}

static void handle_client(int fd) {
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);

    alarm(2);

    const char *banner = "Welcome! Tell me your wish\n";
    (void)write(fd, banner, strlen(banner));

    read_data(fd);

    const char *ok = "OK\n";
    (void)write(fd, ok, strlen(ok));
}

int main(int argc, char **argv) {
    setup();

    int port = 4444;
    if (argc == 2) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port\n");
            return 1;
        }
    }

    signal(SIGCHLD, reap_children);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(s, 16) < 0) {
        perror("listen");
        return 1;
    }

    printf("Fortune Cookie Server listening on 0.0.0.0:%d\n", port);

    while (1) {
        int fd = accept(s, NULL, NULL);
        if (fd < 0) {
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(fd);
            continue;
        }

        if (pid == 0) {
            close(s);
            handle_client(fd);
            close(fd);
            _exit(0);
        }

        close(fd);
    }
}
