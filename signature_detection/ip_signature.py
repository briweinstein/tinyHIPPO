from .signature import Signature
import ipaddress
import scapy.layers.inet as net
from virustotal_checker import VirusTotalChecker

'''
This signature detects whether the packet is communicating with a malicious IP address 
'''


class IPSignature(Signature):
    '''
    - subnet: local ip space for this network
    '''

    def __init__(self, subnet: str):
        self.subnet = ipaddress.ip_network(subnet)

    def __call__(self, packet):
        if net.IP not in packet:
            raise Exception
        ip_layer = packet[net.IP]
        # check whether source ip is private
        ip_src = ipaddress.ip_address(ip_layer.src)
        ip_dst = ipaddress.ip_address(ip_layer.dst)
        if not ip_src.is_private:
            v = VirusTotalChecker()
            return v.check_ip(ip_src) or v.check_ip(ip_dst)
        else:
            return False
