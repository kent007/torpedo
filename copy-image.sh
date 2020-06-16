#!/bin/bash

# to start the VM
#qemu-system-x86_64 -kernel $KERNEL/arch/x86/boot/bzImage -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0"
   #\ -hda $IMAGE/stretch.img -net user,hostfwd=tcp::10021-:22 -net nic -enable-kvm -nographic \
   #\ -m 2G -smp 2 -pidfile vm.pid 2>&1 | tee vm.log

#once started
echo "saving image..."
sudo docker save -o syzkaller-image.tar syzkaller-image
echo "copying image tar..."
sudo scp -i $IMAGE/stretch.id_rsa -P 10021 -o "StrictHostKeyChecking no" syzkaller-image.tar root@localhost:~
echo "loading image on host..."
sudo ssh -i $IMAGE/stretch.id_rsa -p 10021 -o "StrictHostKeyChecking no" root@localhost "docker load -i syzkaller-image.tar && docker image prune"
#echo "copying wrapper source..."
#sudo scp -i $IMAGE/stretch.id_rsa -P 10021 -o "StrictHostKeyChecking no" wrapper.c root@localhost:/wrapper.c
#echo "building wrapper..."
#sudo ssh -i $IMAGE/stretch.id_rsa -p 10021 -o "StrictHostKeyChecking no" root@localhost gcc -o /docker_wrapper /wrapper.c -Wall -Werror
echo "copying fuzzer for testing purposes..."
./copy-fuzzer.sh
