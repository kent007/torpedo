FROM ubuntu:focal
ARG OS
ARG ARCH

RUN apt update
RUN apt install strace -y

COPY ${OS}_${ARCH}/docker-bootstrap /docker-bootstrap
COPY ${OS}_${ARCH}/syz-executor /syz-executor
COPY ./swrapper /swrapper
COPY ./repro-entrypoint.sh /repro-entrypoint.sh
COPY ./repro-nodir.sh /repro-nodir.sh

# pass along all args from command line
ENTRYPOINT ["/docker-bootstrap"]

