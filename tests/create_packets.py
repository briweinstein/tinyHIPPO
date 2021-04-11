#! /usr/bin/env python3

from scapy.all import *

send(IP()/TCP(dport=80)/"Hello World, tinyHIPPO@fake.com, Hello World, password, Hello World", iface='wlan0', inter=5.0, loop=1)

