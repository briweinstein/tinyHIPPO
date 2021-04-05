#!/bin/bash

# Uninstall the old cids package
echo 'Uninstalling old tinyHIPPO package'
$HOME/source/scripts/feeds uninstall tinyHIPPO


echo 'Going into the repo and changing to the main branch'
cd $HOME/OpenWrt-IoT-IDS-Privacy && git checkout main

echo 'Removing old files in tinyHIPPO'
rm -r $HOME/mypackages/examples/tinyHIPPO/src/*

echo 'Copying over the new files'
cp -r $HOME/OpenWrt-IoT-IDS-Privacy/* $HOME/mypackages/examples/tinyHIPPO/src

echo 'Updating package feeds to include new tinyHIPPO'
$HOME/source/scripts/feeds update mypackages

echo 'Installing the new tinyHIPPOdev in the package feeds'
$HOME/source/scripts/feeds install -a -p mypackages

echo 'Running make menuconfig'
cd $HOME/source/ && make menuconfig

echo 'COMPILING'
cd $HOME/source/ && sudo make package/tinyHIPPO/compile V=sc
