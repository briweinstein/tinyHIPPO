# Compiling tinyHIPPO from Source

This document will instruct you through the process of compiling the tinyHIPPO OpenWrt package from source. Please note this is different than running `opkg install tinyHIPPO` on a router with OpenWrt on it.

#### Misc. Notes
This process will require access to some Unix based operating system, and the procedure outlined below used an Ubuntu 20.04 virtual machine

This process also assumes all the directories created are in the user's home directory

This process emulates the developer guide outlined at https://openwrt.org/docs/guide-developer/helloworld/start

Credit for most of this procedure goes to the amazing folks over at OpenWrt.

## Procedure

###  Preparing Your System For Use
First, clone the OpenWrt git repository:
```git clone https://git.openwrt.org/openwrt/openwrt.git source```
This will create the `source` directory in the home directory

Second, we need to build any possible artifacts.
```
cd $HOME/source
make distclean
```
Third, it is recommended to update and install the feeds packages to avoid any future potential problems.
```
./scripts/feeds update -a
./scripts/feeds install -a
```

Fourth, we need to configure the cross-compilation toolchain by using the graphical configuration menu:
```
make menuconfig
```
The key in this step is to select the proper 'Target System', 'Subtarget', and 'Target Profile'. After making the selections, save your changes before exiting.

Now, we can build the cross-compilation toolchain:
```
make toolchain/install
```
From personal experience, this step can take upwards of multiple hours, so grab a cup of coffee, walk the dog, and or read a book, it will be a while.

Once we are finished building the toolchain, we need to make a slight adjustment to the path variable:
```
export PATH=$HOME/source/staging_dir/host/bin:$PATH
```

## Creating a Package
Now we can begin the process of creating the actual package
```
cd $HOME
mkdir -p mypackages/examples/tinyHIPPO
mkdir -p mypackages/examples/tinyHIPPO/src
```
Next, copy over the Makefile included in this directory to the tinyHIPPO directory.

```
cp Makefile $HOME/mypackages/examples/tinyHIPPO
```
## Including New Package Feeds
In order for us to compile the package properly, we need to ensure that we have linked the appropriate feeds.
```
cd $HOME/source
touch feeds.conf
```
And with your favorite text editor (i.e. Vim) add the following to feeds.conf
```
src-link mypackages $HOME/mypackages
```

## Compiling the Package
Now, run the script included in this directory from the terminal
```
./compile_tinyHIPPO_from_source.sh
```
This copy over the appropriate files to their proper locations, and compile the package. 

The resulting *.ipk file will be located in 
```
$HOME/source/bin/packages/<arch>/mypackages
```
## Installing the Package
Copy over the *.ipk file to the router and then run:
```
opkg install <file>
```
Now tinyHIPPO should be up and running on the router!
