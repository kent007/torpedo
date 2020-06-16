// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//this package piggybacks off the existing qemu VM impl to boot docker containers and run them on the VM
package docker

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

const (
	hostAddr = "10.0.2.10"
)

func init() {
	vmimpl.Register("dockerhost", ctor, true)
}

type Config struct {
	Count    int    `json:"count"`     // number of VMs to run in parallel
	Qemu     string `json:"qemu"`      // qemu binary name (qemu-system-arch by default)
	QemuArgs string `json:"qemu_args"` // additional command line arguments for qemu binary
	// Location of the kernel for injected boot (e.g. arch/x86/boot/bzImage, optional).
	// This is passed to qemu as the -kernel option.
	Kernel string `json:"kernel"`
	// Additional command line options for the booting kernel, for example `root=/dev/sda1`.
	// Can only be specified with kernel.
	Cmdline string `json:"cmdline"`
	Initrd  string `json:"initrd"` // linux initial ramdisk. (optional)
	// qemu image device.
	// The default value "hda" is transformed to "-hda image" for qemu.
	// The modern way of describing qemu hard disks is supported, so the value
	// "drive index=0,media=disk,file=" is transformed to "-drive index=0,media=disk,file=image"
	// for qemu.
	ImageDevice string `json:"image_device"`
	CPU         int    `json:"cpu"`      // number of VM CPUs
	Mem         int    `json:"mem"`      // amount of VM memory in MiB
	Snapshot    bool   `json:"snapshot"` // For building kernels without -snapshot (for pkg/build)
}

type Pool struct {
	env        *vmimpl.Env
	cfg        *Config
	target     *targets.Target
	archConfig *archConfig
}

type instance struct {
	cfg        *Config
	target     *targets.Target
	archConfig *archConfig
	image      string
	debug      bool
	os         string
	workdir    string
	sshkey     string
	sshuser    string
	port       int
	rpipe      io.ReadCloser
	wpipe      io.WriteCloser
	qemu       *exec.Cmd
	merger     *vmimpl.OutputMerger
	files      map[string]string
	diagnose   chan bool
}

type archConfig struct {
	Qemu      string
	QemuArgs  string
	TargetDir string
	NicModel  string
	CmdLine   []string
}

//added net.ifnames=0 here to fix the networking problem on the disk I have
var archConfigs = map[string]*archConfig{
	"linux/amd64": {
		Qemu:      "qemu-system-x86_64",
		QemuArgs:  "-enable-kvm -cpu host,migratable=off",
		TargetDir: "/",
		// e1000e fails on recent Debian distros with:
		// Initialization of device e1000e failed: failed to find romfile "efi-e1000e.rom
		// But other arches don't use e1000e, e.g. arm64 uses virtio by default.
		NicModel: ",model=e1000",
		CmdLine: append(linuxCmdline,
			"root=/dev/sda",
			"console=ttyS0",
			"kvm-intel.nested=1",
			"kvm-intel.unrestricted_guest=1",
			"kvm-intel.vmm_exclusive=1",
			"kvm-intel.fasteoi=1",
			"kvm-intel.ept=1",
			"kvm-intel.flexpriority=1",
			"kvm-intel.vpid=1",
			"kvm-intel.emulate_invalid_guest_state=1",
			"kvm-intel.eptad=1",
			"kvm-intel.enable_shadow_vmcs=1",
			"kvm-intel.pml=1",
			"kvm-intel.enable_apicv=1",
			"net.ifnames=0",
		),
	},
	"linux/386": {
		Qemu:      "qemu-system-i386",
		TargetDir: "/",
		NicModel:  ",model=e1000",
		CmdLine: append(linuxCmdline,
			"root=/dev/sda",
			"console=ttyS0",
		),
	},
	"linux/arm64": {
		Qemu:      "qemu-system-aarch64",
		QemuArgs:  "-machine virt,virtualization=on -cpu cortex-a57",
		TargetDir: "/",
		CmdLine: append(linuxCmdline,
			"root=/dev/vda",
			"console=ttyAMA0",
		),
	},
	"linux/arm": {
		Qemu:      "qemu-system-arm",
		TargetDir: "/",
		CmdLine: append(linuxCmdline,
			"root=/dev/vda",
			"console=ttyAMA0",
		),
	},
	"linux/mips64le": {
		Qemu:      "qemu-system-mips64el",
		TargetDir: "/",
		QemuArgs:  "-M malta -cpu MIPS64R2-generic -nodefaults",
		NicModel:  ",model=e1000",
		CmdLine: append(linuxCmdline,
			"root=/dev/sda",
			"console=ttyS0",
		),
	},
	"linux/ppc64le": {
		Qemu:      "qemu-system-ppc64",
		TargetDir: "/",
		QemuArgs:  "-enable-kvm -vga none",
		CmdLine:   linuxCmdline,
	},
	"freebsd/amd64": {
		Qemu:      "qemu-system-x86_64",
		TargetDir: "/",
		QemuArgs:  "-enable-kvm",
		NicModel:  ",model=e1000",
	},
	"netbsd/amd64": {
		Qemu:      "qemu-system-x86_64",
		TargetDir: "/",
		QemuArgs:  "-enable-kvm",
		NicModel:  ",model=e1000",
	},
	"fuchsia/amd64": {
		Qemu:      "qemu-system-x86_64",
		QemuArgs:  "-enable-kvm -machine q35 -cpu host,migratable=off",
		TargetDir: "/tmp",
		NicModel:  ",model=e1000",
		CmdLine: []string{
			"kernel.serial=legacy",
			"kernel.halt-on-panic=true",
		},
	},
	"akaros/amd64": {
		Qemu:      "qemu-system-x86_64",
		QemuArgs:  "-enable-kvm -cpu host,migratable=off",
		TargetDir: "/",
		NicModel:  ",model=e1000",
	},
}

var linuxCmdline = []string{
	"earlyprintk=serial",
	"oops=panic",
	"nmi_watchdog=panic",
	"panic_on_warn=1",
	"panic=1",
	"ftrace_dump_on_oops=orig_cpu",
	"rodata=n",
	"vsyscall=native",
	"net.ifnames=0",
	"biosdevname=0",
}

//called as a constructor for the object, it's bound to init()
//reads the config and returns a pool object
func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	archConfig := archConfigs[env.OS+"/"+env.Arch]
	cfg := &Config{
		Count:       1,
		CPU:         1,
		ImageDevice: "hda",
		Qemu:        archConfig.Qemu,
		QemuArgs:    archConfig.QemuArgs,
		Snapshot:    true,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse qemu vm config: %v", err)
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	if env.Debug && cfg.Count > 1 {
		log.Logf(0, "limiting number of VMs from %v to 1 in debug mode", cfg.Count)
		cfg.Count = 1
	}
	if _, err := exec.LookPath(cfg.Qemu); err != nil {
		return nil, err
	}
	if env.Image == "9p" {
		if env.OS != "linux" {
			return nil, fmt.Errorf("9p image is supported for linux only")
		}
		if cfg.Kernel == "" {
			return nil, fmt.Errorf("9p image requires kernel")
		}
	} else {
		if !osutil.IsExist(env.Image) {
			return nil, fmt.Errorf("image file '%v' does not exist", env.Image)
		}
	}
	if cfg.CPU <= 0 || cfg.CPU > 1024 {
		return nil, fmt.Errorf("bad qemu cpu: %v, want [1-1024]", cfg.CPU)
	}
	if cfg.Mem < 128 || cfg.Mem > 1048576 {
		return nil, fmt.Errorf("bad qemu mem: %v, want [128-1048576]", cfg.Mem)
	}
	cfg.Kernel = osutil.Abs(cfg.Kernel)
	cfg.Initrd = osutil.Abs(cfg.Initrd)
	pool := &Pool{
		env:        env,
		cfg:        cfg,
		target:     targets.Get(env.OS, env.Arch),
		archConfig: archConfig,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

//create a new pool
func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	sshkey := pool.env.SSHKey
	sshuser := pool.env.SSHUser
	if pool.env.Image == "9p" {
		sshkey = filepath.Join(workdir, "key")
		sshuser = "root"
		if _, err := osutil.RunCmd(10*time.Minute, "", "ssh-keygen", "-t", "rsa", "-b", "2048",
			"-N", "", "-C", "", "-f", sshkey); err != nil {
			return nil, err
		}
		initFile := filepath.Join(workdir, "init.sh")
		if err := osutil.WriteExecFile(initFile, []byte(strings.Replace(initScript, "{{KEY}}", sshkey, -1))); err != nil {
			return nil, fmt.Errorf("failed to create init file: %v", err)
		}
	}

	for i := 0; ; i++ {
		inst, err := pool.ctor(workdir, sshkey, sshuser, index)
		if err == nil {
			return inst, nil
		}
		// Older qemu prints "could", newer -- "Could".
		if i < 1000 && strings.Contains(err.Error(), "ould not set up host forwarding rule") {
			continue
		}
		return nil, err
	}
}

//constructor for the VM
//calls boot, which brings up the VM and forwards ssh
//for this instance, we don't need a VM, so it really goes away
func (pool *Pool) ctor(workdir, sshkey, sshuser string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		cfg:        pool.cfg,
		target:     pool.target,
		archConfig: pool.archConfig,
		image:      pool.env.Image,
		debug:      pool.env.Debug,
		os:         pool.env.OS,
		workdir:    workdir,
		sshkey:     sshkey,
		sshuser:    sshuser,
		diagnose:   make(chan bool, 1),
	}
	//put the outputmerger in here, migrated from boot
	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)
	return inst, nil
}

func (inst *instance) Close() {
	log.Logf(1, "no VM was started, Close does nothing")
}

//necessary to return loopback, since we're running on the host
func (inst *instance) Forward(port int) (string, error) {
	addr := "127.0.0.1"
	return fmt.Sprintf("%v:%v", addr, port), nil
}

func (inst *instance) targetDir() string {
	if inst.image == "9p" {
		return "/tmp"
	}
	return inst.archConfig.TargetDir
}

//copy a file from the host to the VM
func (inst *instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	//vmDst := filepath.Join(inst.targetDir(), base)
	if base == "syz-executor" {
		//this is already on the docker image loaded in the VM, so it won't be necessary to copy it
		//we need to specify the path inside the container though
		return "/syz-executor", nil
	}
	if base == "syz-fuzzer" {
		//this is the entrypoint of the docker container
		//on the host, return the location of the bootstrap
		return "/home/kent/gopath/src/github.com/google/syzkaller/bin/linux_amd64/docker-bootstrap", nil
	}
	log.Logf(1, "'Copy' was called for something besides the executor or the fuzzer, so ignoring it")
	return "", nil
}

//run actually runs the command, normally through ssh
//on the host, no SSH is necessary
func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	inst.merger.Add("ssh", rpipe)
	args := strings.Split(command, " ")
	if inst.debug {
		log.Logf(0, "running command: %#v", args)
	}
	cmd := osutil.Command(args[0], args[1:]...)
	cmd.Dir = inst.workdir
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		return nil, nil, err
	}
	wpipe.Close()
	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}

	go func() {
	retry:
		select {
		case <-time.After(timeout):
			signal(vmimpl.ErrTimeout)
		case <-stop:
			signal(vmimpl.ErrTimeout)
		case <-inst.diagnose:
			cmd.Process.Kill()
			goto retry
		case err := <-inst.merger.Err:
			cmd.Process.Kill()
			if cmdErr := cmd.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			}
			signal(err)
			return
		}
		cmd.Process.Kill()
		cmd.Wait()
	}()
	return inst.merger.Output, errc, nil
}

func (inst *instance) Diagnose() ([]byte, bool) {
	select {
	case inst.diagnose <- true:
	default:
	}
	return nil, false
}

// nolint: lll
const initScript = `#! /bin/bash
set -eux
mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs nodev /sys/kernel/debug/
mount -t tmpfs none /tmp
mount -t tmpfs none /var
mount -t tmpfs none /run
mount -t tmpfs none /etc
mount -t tmpfs none /root
touch /etc/fstab
mkdir /etc/network
mkdir /run/network
printf 'auto lo\niface lo inet loopback\n\n' >> /etc/network/interfaces
printf 'auto eth0\niface eth0 inet static\naddress 10.0.2.15\nnetmask 255.255.255.0\nnetwork 10.0.2.0\ngateway 10.0.2.1\nbroadcast 10.0.2.255\n\n' >> /etc/network/interfaces
printf 'auto eth0\niface eth0 inet6 static\naddress fe80::5054:ff:fe12:3456/64\ngateway 2000:da8:203:612:0:3:0:1\n\n' >> /etc/network/interfaces
mkdir -p /etc/network/if-pre-up.d
mkdir -p /etc/network/if-up.d
ifup lo
ifup eth0 || true
echo "root::0:0:root:/root:/bin/bash" > /etc/passwd
mkdir -p /etc/ssh
cp {{KEY}}.pub /root/
chmod 0700 /root
chmod 0600 /root/key.pub
mkdir -p /var/run/sshd/
chmod 700 /var/run/sshd
groupadd -g 33 sshd
useradd -u 33 -g 33 -c sshd -d / sshd
cat > /etc/ssh/sshd_config <<EOF
          Port 22
          Protocol 2
          UsePrivilegeSeparation no
          HostKey {{KEY}}
          PermitRootLogin yes
          AuthenticationMethods publickey
          ChallengeResponseAuthentication no
          AuthorizedKeysFile /root/key.pub
          IgnoreUserKnownHosts yes
          AllowUsers root
          LogLevel INFO
          TCPKeepAlive yes
          RSAAuthentication yes
          PubkeyAuthentication yes
EOF
/usr/sbin/sshd -e -D
/sbin/halt -f
`
