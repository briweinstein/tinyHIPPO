#! /usr/bin/env python3

from scapy.all import send
from scapy.layers.inet import TCP, IP

send(IP()/TCP(dport=80)/"123121234", iface='wlan0', inter=5.0, loop=1)

