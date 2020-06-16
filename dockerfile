from debian:9

COPY syz-executor .
COPY syz-fuzzer .

# pass along all args from command line
ENTRYPOINT ["/syz-fuzzer"]

