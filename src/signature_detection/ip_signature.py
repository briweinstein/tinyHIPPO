from .signature import Signature
import ipaddress
import scapy.layers.inet as net
from scapy.packet import Packet
from .virustotal_checker import VirusTotalChecker
from src import run_config


class IPSignature(Signature):
    """
    This signature detects whether the packet is communicating with a malicious IP address
    """

    def __init__(self, subnet: str):
        """
        Creates this IPSignature
        :param subnet: The subnet that this router uses in CIDR form, ex. 192.168.1.0/24
        """
        self.subnet = ipaddress.ip_network(subnet)
        self.v = VirusTotalChecker(run_config.virustotal_api_key)

    def __call__(self, packet: Packet) -> bool:
        if net.IP not in packet:
            raise Exception('IP Layer not present in packet')
        ip_layer = packet[net.IP]
        # check whether source ip is private
        ip_src = ipaddress.ip_address(ip_layer.src)
        ip_dst = ipaddress.ip_address(ip_layer.dst)
        if not ip_src.is_private:
            return self.v.check_ip(ip_src)
        else:
            return self.v.check_ip(ip_dst)