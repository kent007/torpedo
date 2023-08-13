# TORPEDO

In order to build, execute the following steps

1. `make ADDCFLAGS="-Wno-unused-function -pthread"`
2. `make-docker-image.sh OS=linux ARCH=amd64`

# Torpedo config options

In config/docker.json, see the following options to control torpedo-specific features

* `seeds`: a directory containing seed files. If this directory is empty, syzkaller will instead generate seeds as normal
* `runtime`: controls what container runtime is selected
* `capabilities`: controls what capabilities are given to the container, useful for testing certain syscalls that require elevated permissions
