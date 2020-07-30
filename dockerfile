from debian:9

COPY linux_amd64/ /bin/linux_amd64/
COPY syz-manager .
COPY configs/ configs/

# pass along all args from command line
ENTRYPOINT ["/bin/linux_amd64/syz-fuzzer"]

