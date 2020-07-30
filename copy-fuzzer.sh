#!/usr/bin/env bash

#sudo scp -i $IMAGE/stretch.id_rsa -P 10021 -o "StrictHostKeyChecking no" bin/linux_amd64/docker-bootstrap root@localhost:/docker-bootstrap
sudo scp -r -i $IMAGE/stretch.id_rsa -P 10021 -o "StrictHostKeyChecking no" bin/linux_amd64  root@localhost:/bin/linux_amd64
sudo scp -i $IMAGE/stretch.id_rsa -P 10021 -o "StrictHostKeyChecking no" bin/syz-manager root@localhost:/syz-manager
#sudo scp -i $IMAGE/stretch.id_rsa -P 10021 -o "StrictHostKeyChecking no" -r /home/kent/gopath/src/github.com/google/syzkaller/pkg/ipc/ root@localhost:/home/kent/gopath/src/github.com/google/syzkaller/pkg/ipc/
#sudo scp -i $IMAGE/stretch.id_rsa -P 10021 -o "StrictHostKeyChecking no" -r /home/kent/gopath/src/github.com/google/syzkaller/syz-fuzzer/ root@localhost:/home/kent/gopath/src/github.com/google/syzkaller/syz-fuzzer/
