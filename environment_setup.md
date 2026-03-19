# Environment Setup Guide
## Offensive Security Lab, Apple Silicon Mac + UTM

---

## 1. Why this setup

The lab binaries are x86-64 Linux binaries. Apple Silicon Macs are ARM, so the binaries cannot run natively on macOS. UTM with QEMU emulation provides an x86-64 Linux environment that runs them correctly.

---

## 2. Install UTM

```bash
brew install --cask utm
```

Or download directly from https://mac.getutm.app.

---

## 3. Download Ubuntu 22.04 x86-64 Server ISO

```
https://releases.ubuntu.com/22.04/ubuntu-22.04.5-live-server-amd64.iso
```

Use the **x86-64** ISO, not ARM.

---

## 4. Create the VM in UTM

1. Open UTM, click **Create a New Virtual Machine**
2. Choose **Emulate** (not Virtualize)
3. Select **Linux**, confirm architecture is **x86-64**
4. Select the downloaded ISO
5. RAM: 4096 MB recommended, 2048 MB minimum
6. Disk: 20 GB
7. Name it and save

---

## 5. Install Ubuntu

Go through the installer:

- **Mirror**: leave default (auto-detected for your region)
- **Storage**: use entire disk, LVM enabled, no encryption
- **Profile**: set your username and password
- **SSH**: enable OpenSSH server
- **Snaps**: skip everything, hit Done

When prompted to reboot, eject the ISO from UTM's CD/DVD drive settings first, then press Enter.

---

## 6. Connect via SSH

Typing in the UTM window has no copy-paste support. Connect from your Mac terminal instead.

Get the VM's IP inside the VM:
```bash
ip a
# look for the address next to enp0s1, e.g. 192.168.64.x
```

Then from the Mac terminal:
```bash
ssh youruser@192.168.64.x
```

---

## 7. Install tools

Run all of these inside the VM over SSH.

### System packages
```bash
sudo apt update && sudo apt install -y \
    python3 python3-pip \
    gdb git curl wget \
    file binutils cmake \
    build-essential
```

### Python tools
```bash
pip3 install pwntools ropgadget
```

### Fix PATH for pip-installed scripts
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### pwndbg
```bash
git clone https://github.com/pwndbg/pwndbg ~/pwndbg
cd ~/pwndbg && ./setup.sh
```

### Verify
```bash
python3 -c "from pwn import *; print('pwntools ok')"
gdb --version
ROPgadget --version
```

---

## 8. Shared folder

### UTM settings

With the VM stopped, go to UTM VM settings, Sharing:
- Directory Share Mode: **VirtFS**
- Path: browse and select your lab folder on the Mac

### Mount inside the VM

```bash
sudo mkdir -p /mnt/labs
sudo mount -t 9p -o trans=virtio,version=9p2000.L share /mnt/labs
sudo chmod -R 755 /mnt/labs
```

### Auto-mount on boot

```bash
echo 'share /mnt/labs 9p trans=virtio,version=9p2000.L,rw,nofail 0 0' | sudo tee -a /etc/fstab
```

### Verify

```bash
ls /mnt/labs
```

Your Mac lab files should appear here.
