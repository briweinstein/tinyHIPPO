# OpenWrt Package Development Notes

The following is a series of important notes for developing an OpenWrt package.

To learn basic package development, the tutorial provided by OpenWrt was followed:
https://openwrt.org/docs/guide-developer/helloworld/start

The following are notes about the process and major pitfalls. Please refer to these notes and the tutorial for how to construct a basic OpenWrt package

## Requirements
Before compiling an OpenWrt package, numerous additional packages need to be installed onto your machine.
The easiest way for me to do this was to do it on a separate virtual machine.
With Ubuntu 20.04, I ran the following to install all the libraries:

* sudo apt install bash binutils bzip2 flex git-core g++ gcc util-linux gawk help2man intltool libelf-dev zlib1g-dev make libncurses5-dev libssl-dev patch perl-modules python2-dev unzip wget gettext xsltproc zlib1g-dev

Note: If you are compiling the package on a VM, make sure you allocate at least 32GB of disk space as it requires a lot of space

## Prepping OpenWrt Build System
The following commands are used to start the build system:
* git clone https://git.openwrt.org/openwrt/openwrt.git source
* cd source
* make distclean
* ./scripts/feeds update -a
* ./scripts/feeds install -a
* make menuconfig
* make toolchain/install

IMPORTANT NOTES:
* The tutorial will checkout a stable code version, v17.01.2, however this will result in errors, use the latest commit as it will work
* For make menuconfig, use the following settings:
    * Target System: MediaTek Ralink MIPS
    * Subtarget: MT7621 based borads
    * Target Profile: NETGEAR R6350 (the router we have)
* The command make toolchain/install will take HOURS so relax and do other work while everything compiles

## Creating the Actual Package
The actual package is not difficult to develop. It is just referencing the source code of the program and having a OpenWrt Makefile which will compile your program.

An example OpenWrt Makefile is provided in this directory, named 'Makefile_Example'

To compile the package itself, use the following command:

* make package/helloworld/compile

Once that is complete, the result will be a helloworld_1.0-1_<arch>.ipk file

NOTES:
* Make sure you use tabs NOT SPACES for indentation in the OpenWrt Makefile, there will be errors compiling otherwise

## Installing the package
Copy over the package to the OpenWrt router and run the following:

* opkg install /tmp/helloworld_1.0-1_<arch>.ipk

And boom, it should install properly and you have created your first package!

These are just the important notes to avoid some of the pitfalls I encountered when I was first creating a package,
but the documentation should be read on how to create a HelloWorld package here: https://openwrt.org/docs/guide-developer/helloworld/start