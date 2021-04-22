from .signature import Signature
from src import run_config
import scapy.layers.inet as net
from scapy.all import Packet
import ipaddress

from ..database.models import DeviceInformation


class MACAddressSignature(Signature):
    """
    This signature detects whether the comes from a trusted device on the network
    """

    def __call__(self, packet: Packet) -> bool:
        """
        This method returns True if the src mac address is not in the network and the source ip is private, which would
        indicate an unauthorized IoT device within the network or MACAddress spoofing
        :param packet:The packet to check for MAC Address spoofing
        :return: Whether the packet came from a spoofed MAC Address
        """
        if net.Ether not in packet or net.IP not in packet:
            return False
            # raise Exception("MACAddressSignature: Given packet does not have the necessary layers")
        ether_layer = packet[net.Ether]
        ip_layer = packet[net.IP]
        mac_src = ether_layer.src
        ip_src = ipaddress.ip_address(ip_layer.src)
        return ip_src.is_private and (mac_src not in DeviceInformation.get_mac_addresses())
