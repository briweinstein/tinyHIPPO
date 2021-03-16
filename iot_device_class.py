#! /usr/bin/env python3
from mitm.mitm import MitM


class IoTDevice:
    def __init__(self, mac_addr):
        self.mac_addr = mac_addr
        self.mitm = MitM()



