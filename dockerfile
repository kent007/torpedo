from debian:9

COPY test_64/docker-bootstrap /docker-bootstrap
COPY test_64/syz-executor /syz-executor

# pass along all args from command line
ENTRYPOINT ["/docker-bootstrap"]

