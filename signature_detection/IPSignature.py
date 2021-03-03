from .Signature import Signature
import ipaddress
import scapy.layers.inet as net


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
        if not ipaddress.ip_address(ip_layer.src).is_private:
            # TODO: if not private check whether it's from a trusted source eg check virustotal
            print(f'incoming packet: {ip_layer.src}')
        else:
            # TODO:if outgoing check mac addresses against config and ensure it's coming from a user verified space
            # TODO: if outgoing
            print(f'outgoing packet: {ip_layer.src}')
