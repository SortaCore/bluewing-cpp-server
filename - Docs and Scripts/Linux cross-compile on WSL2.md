# Setting up Linux cross-compile on VS using lccalhost WSL2

## OS recommendations
Recommended for bluewing-cpp-server-linux is Ubuntu 18.04 LTS.  
You need to install the dated g++7; this is the earliest g++ that supports C++17.
It comes with the earliest libc, and earliest libc is a hard minimum OS compatibility.
The usual practice is to build against the oldest libc/libstdc++ that you can,
and load the most recent at runtime.

Older gcc/g++ will build correctly, but not be backwards-compatible earlier than the libc it was built with.  
See [this table][GCC compat table] on g++/clang vs Ubuntu compatible.

On any Linux variant, you can run `ldd --version ldd` to see the libc version.

## WSL2 networking note
WSL2 is best operated in [Mirrored networking mode][Mirrored], configured in [.wslconfig][wslconfig],
which you normally create at C:\\Users\\YourUser\\.wslconfig.  
WSL comes with a tool for editing this config, called WSLconfig, but Notepad suffices.  
If you edit by hand, note the INI does not support semi-colon comments.  
```ini
[wsl2]
networkingMode=mirrored```

This is recommended for host <-> WSL access. You can connect to it via localhost or 127.0.0.1.  
Note that other 127 addresses will not work, including the 127 IP reported by WSL.  

If you use mirrored mode, you need the Windows Hypervisor Platform feature as well, or you will get an error code
on WSL start and it will fall back to None networking.  
If you edited wslconfig, you must restart wsl with `wsl --shutdown`.

## WSL2 DNS failure
If you get DNS lookups converting to IPs in WSL properly, but outgoing connections fail, there is a fix.  
This will look like running `apt update` and getting `Connecting (archive.ubuntu.org (84.x.x.x)`.

To fix it, run this in admin PowerShell:
```ps
Set-NetFirewallHyperVVMSetting -Name '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -DefaultInboundAction Allow -DefaultOutboundAction Allow```

This may only be a problem if your Windows Firewall is set to block outgoing connections by default,
a feature of [Malwarebytes Windows Firewall Control][WFC].

## WSL2 on IPv4 only
If you are on an IPv4-only network, do not turn off WSL2 IPv6 via kernel options.  
IPv6 not being available is not supported by WSL creators.  
Some things such as IPv6 link-local addresses are expected to exist.  
Instead, tell WSL2 to prefer IPv4 over IPv6 by uncommenting [some lines][gai] in `/etc/gai.conf`.


# Installing Ubuntu
First, in admin PowerShell:
```ps
Invoke-WebRequest -Uri https://aka.ms/wsl-ubuntu-1804 -OutFile Ubuntu.appx -UseBasicParsing
Add-AppxPackage .\Ubuntu.appx
ubuntu1804```
It will ask for Linux user and password.

# Update Ubuntu
After that, do the following shell commands:
```bash
#!/bin/bash
sudo su
apt update```

# Cross chain compiler install
To add support for older gcc/g++:
```bash
add-apt-repository ppa:jonathonf/gcc
apt update```
  
Note that the commented lines later are excluding x86_64 toolchain.  
This is because the native GCC compiler has no suffix, and it is assumed you are using x86_64 Ubuntu.  
If you are not, you may have to edit comments here and in later scripts.  

Soft float ARM ABI is usable, but most Linux OSes are hard float, including Raspberry Pi.  
If you do know you have a Linux client OS that is soft-float ARM, then you should install gnueabi
in addition to gnueabihf.  
A use of soft-float on hard-float CPU may result in SIGFPE before the first line executes.

Then, to install [VS required features][VS required features], and cross-compiler variants.
```bash
apt-get install openssh-server gdb make ninja-build rsync zip
apt-get install gcc-7 g++7
# apt-get install gcc-7-x86-64-linux-gnu g++-7-x86-64-linux-gnu
apt-get install gcc-7-aarch64-linux-gnu g++-7-aarch64-linux-gnu
apt-get install gcc-7-i686-linux-gnu g++-7-i686-linux-gnu
apt-get install gcc-7-arm-linux-gnueabihf g++-7-arm-linux-gnueabihf```

Next, we symlink all the suffixed toolchains to be the default version.  
This is not required, but you will have to edit the project configuration in VS to specify
the 7 suffix if you don't.  
```bash
cd /usr/bin
#ln x86-64-linux-gnueabi-g++-7 x86-64-linux-gnueabi-g++
#ln x86-64-linux-gnueabi-gcc-7 x86-64-linux-gnueabi-gcc
ln gcc-7 gcc
ln g++-7 g++
ln arm-linux-gnueabihf-g++-7 arm-linux-gnueabihf-g++
ln arm-linux-gnueabihf-gcc-7 arm-linux-gnueabihf-gcc
ln aarch64-linux-gnu-g++-7 aarch64-linux-gnu-g++
ln aarch64-linux-gnu-gcc-7 aarch64-linux-gnu-gcc
ln i686-linux-gnu-g++-7 i686-linux-gnu-g++
ln i686-linux-gnu-gcc-7 i686-linux-gnu-gcc```

# Setting up remote build
You have ssh server installed by earlier apt install, but the service is not running yet.  
First, edit ssh config:
```bash
nano /etc/ssh/sshd_config```
Change `ListenAddress 0.0.0.0` to `ListenAddress 127.0.0.1`
Change `PasswordAuthentication no` to `PasswordAuthentication yes`

(To save and exit nano after editing, press Ctrl-X, then Y, then Enter.)

This config changes allows password login and prevents remote access outside of localhost.  
If you want LAN access, not just localhost, adjust ListenAddress to your LAN subnet accordingly.  
If you want building from outside LAN, you had best not use password authentication,  
not use the default port 22, and ideally, limit your listen address, as well as external IP
range on your router's port forwarding.  
Consider running WSL on the other side you were remoting from, instead. WSL is meant to avoid
the lag that comes from external building, after all.

Now ssh is configured, start the ssh service:
```bash
service ssh start```

You should then be able to link VS to localhost WSL2 server.  

Note if you close the WSL2 console, Ubuntu will close down, shutting down ssh with it,
which means remote building won't work.  
SSH will not auto-start on next WSL start either; you will have to run it again or
configure SSH to start with Linux. To do that, read on:

# Remote building constantly available
To have VS remote builing constantly available, there are 2-3 things to set up.
First, set up WSL to run without a console window.  
Second, set up Linux to start SSH on start.  
Third, optional, set Windows to run WSL on boot.  

## WSL running without a console window
To run WSL perpetually without a console window, you can set up dbus-x11 module:
```bash
sudo apt install dbus-x11
chmod 0700 /mnt/wslg/runtime-dir```

Thereafter, you can start WSL without a required console using:  
```ps
wsl --exec dbus-launch true```

### dbus start error
Give dbus execute a try. You may encounter this error.  
```txt
dbus[15]: Unable to set up transient service directory: XDG_RUNTIME_DIR "/mnt/wslg/runtime-dir" can be written by others (mode 040777)```

This is fixed by running in WSL:  
```bash
sudo nano /etc/wsl.conf```

And editing the file to add WSL startup commands:
```ini
[boot]
command=chmod 0700 /mnt/wslg/runtime-dir```

These commands are run as root user, and you can run multiple by separating with semicolon.

## Enable Linux to run SSH on start
You have two options for having Linux OS start SSH on boot. Choose only one.

### Enable systemd support in WSL2
Option 1, enabling systemd in WSL2 (note [MS docs][MS systemd]).  
This is a significant change and enables support for systemd Linux service management.  
By default, WSL has systemd disabled, and no startup service manager exists;
everything must be manually run, or you must install a different service manager.

If you want to go the systemd enable route, you edit `/etc/wsl.conf` by running in WSL:  
```bash
sudo nano /etc/wsl.conf```

Edit so the contents have `systemd=true` under `boot` group:
```ini
[boot]
systemd=true```
And `boot` may include your `command` fix mentioned in dbus start error section above.

After editing wsl.conf, restart WSL.

Then, in a new WSL window:
```bash
sudo service ssh enable --now```
And from now on your SSH will run on start.

### Edit WSL startup command
Option 2, to avoid enabling systemd, you can edit the WSL startup command:
If you want to go this route, you edit `/etc/wsl.conf` again by running in WSL:  
```bash
sudo nano /etc/wsl.conf```

The contents should be:
```ini
[boot]
command=service ssh start```

Or, if you did the `command` fix mentioned in dbus start error section above, it should be:
```ini
[boot]
command=chmod 0700 /mnt/wslg/runtime-dir;service ssh start```

After editing wsl.conf, restart WSL.

### WSL2 available on Windows start
To run WSL2 on Windows login, consider using a Windows Scheduled Task to run the exec dbus command above.

### Mirrored networking fails
```
Error code: CreateInstance/CreateVm/ConfigureNetworking/0x8007054f
wsl: Failed to configure network (networkingMode Mirrored), falling back to networkingMode None.
```

https://github.com/microsoft/WSL/issues/13454
The quick fix:
```ps1
wsl --shutdown; netsh winsock reset; netsh int ip reset; Restart-Service hns -Force; wsl
```

The hefty fix:
https://github.com/microsoft/WSL/issues/13454#issuecomment-3792804841
Edit IPs if you have static. Run in admin powershell after edits.




### Locale use
Those in the Greatest Britain may wish to do:  
```bash
sudo locale-gen en_GB.UTF-8
sudo update-locale LANG=en_GB.UTF8
```

And restart WSL.


[GCC compat table]: https://askubuntu.com/a/1163021
[VS required features]: https://learn.microsoft.com/en-us/cpp/linux/download-install-and-setup-the-linux-development-workload?view=msvc-170#:~:text=you%20can%20install%20them%20using%20this%20command
[mirrored]: https://learn.microsoft.com/en-us/windows/wsl/networking#mirrored-mode-networking
[wslconfig]: https://learn.microsoft.com/en-us/windows/wsl/wsl-config
[WFC]: https://www.binisoft.org/wfc.php
[gai]: https://askubuntu.com/a/1200257
[MS systemd]: https://learn.microsoft.com/en-us/windows/wsl/systemd#how-to-enable-systemd
