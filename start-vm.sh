#!/bin/bash

sudo qemu-system-x86_64 -kernel $KERNEL/arch/x86/boot/bzImage -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" -hda $IMAGE/stretch.img -net user,hostfwd=tcp::10021-:22 -net nic -enable-kvm -nographic -m 2G -smp 2 -pidfile vm.pid 2>&1 | tee vm.log
