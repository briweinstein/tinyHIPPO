#!/usr/bin/python3

"""
    Note: This interception functionality of this file was created by https://gist.github.com/eXenon/85a3eab09fefbb3bee5d.
    The writers of the tinyHIPPO package have made modifications here to fit this file in with the package.
"""

"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

from mitm.helpers_mitm import get_session_packet_type

import nfqueue
from scapy.all import *
import os

# If you want to use it for MITM :
iptablesr = "iptables -A FORWARD -j NFQUEUE"

print("Adding iptable rules :")
print(iptablesr)
os.system(iptablesr)

# If you want to use it for MITM attacks, set ip_forward=1 :
print("Set ipv4 forward settings : ")
os.system("sysctl net.ipv4.ip_forward=1")

# Drop the packet
# payload.set_verdict(nfqueue.NF_DROP)
# Modify the packet, copy and modify it with scapy then do:
# payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))


class ScapyBridge:
    def __call__(self, mac_addrs, devices):
        self.mac_addrs = mac_addrs
        self.devices = devices

        # This is the intercept
        q = nfqueue.queue()
        q.open()
        q.bind(socket.AF_INET)
        q.set_callback(self.__callback)
        q.create_queue(0)
        try:
            q.try_run()  # Main loop
        except KeyboardInterrupt:
            q.unbind(socket.AF_INET)
            q.close()

    # TODO: Not sure if the set_callback function will allow this function to be in the object
    def __callback(self, payload):
        # Here is where the magic happens.
        data = payload.get_data()
        packet = IP(data)
        # If the packet is coming or going to one of the IoT devices, process it
        if (packet.src in self.mac_addrs) or (packet.dst in self.mac_addrs):
            # TODO: Call privacy and IDS functions

            # MitM the packet if possible
            if packet.haslayer(TCP):
                # If this packet is part of a possible MitM session, get the session and process the packet
                session_packet_type = get_session_packet_type(packet)
                if session_packet_type:
                    for device in self.devices:
                        device_mitm_session = device.get_mitm_session(packet)
                        device_mitm_session(packet, session_packet_type, payload)
                        return

        # Send the packet on its way
        payload.set_verdict(nfqueue.NF_ACCEPT)

