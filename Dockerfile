FROM ubuntu:focal
ARG OS
ARG ARCH

COPY ${OS}_${ARCH}/docker-bootstrap /docker-bootstrap
COPY ${OS}_${ARCH}/syz-executor /syz-executor

# pass along all args from command line
ENTRYPOINT ["/docker-bootstrap"]

