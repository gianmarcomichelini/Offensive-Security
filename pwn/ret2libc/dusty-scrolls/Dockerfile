FROM ubuntu:24.04

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf
WORKDIR /home/ctf

COPY ret2libc_leak .
RUN chmod +x ret2libc_leak

USER ctf
EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./ret2libc_leak,pty,stderr,setsid,sigint,sane"]
