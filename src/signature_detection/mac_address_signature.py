from .signature import Signature
from src import run_config
import scapy.layers.inet as net
import ipaddress

'''
This signature detects whether the comes from a trusted device on the network 
'''


class MACAddressSignature(Signature):

    def __call__(self, packet):
        """
        This method returns True if the src mac address is not in the network and the source ip is private, which would
        indicate an unauthorized IoT device within the network or MACAddress spoofing
        :param packet:
        :return:
        """
        if net.Ether not in packet or net.IP not in packet:
            raise Exception
        ether_layer = packet[net.Ether]
        ip_layer = packet[net.IP]
        mac_src = ether_layer.src
        ip_src = ipaddress.ip_address(ip_layer.src)
        return ip_src.is_private and (mac_src not in run_config.mac_addrs)
