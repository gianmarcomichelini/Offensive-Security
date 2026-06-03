FROM cybersecnatlab/challenge-jail:ubuntu-noble@sha256:519cc50e62239864cc1f648a123c53c5fe6668772c9f39a0e57c0001e06091a6

ENV SET_INTERPRETER=/home/user/ld-linux.so
ENV SET_RPATH=/home/user/libs
ENV FLAG_IN_ENV=1

COPY account_vault /home/user/chall
COPY ld-linux-x86-64.so.2 /home/user/ld-linux.so
COPY libc.so.6 /home/user/libs/libc.so.6
RUN chmod +x /home/user/chall /home/user/ld-linux.so
