FROM ubuntu:24.04

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf
WORKDIR /home/ctf

COPY libc.so.6 .
RUN chmod +x libc.so.6

USER ctf
EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./libc.so.6,pty,stderr,setsid,sigint,sane"]
