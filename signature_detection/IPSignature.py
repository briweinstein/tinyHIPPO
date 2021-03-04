from .Signature import Signature
import ipaddress
import scapy.layers.inet as net
from VirusTotalChecker import VirusTotalChecker


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
            # TODO: if not private check whether it's from a trusted source eg check virustotal
            v = VirusTotalChecker()
            print(f'incoming packet: {ip_layer.src}')
            return v.check_ip(ip_src) or v.check_ip(ip_dst)
        else:
            # TODO:if outgoing check mac addresses against config and ensure it's coming from a user verified space
            # TODO: if outgoing
            print(f'outgoing packet: {ip_layer.src}')
