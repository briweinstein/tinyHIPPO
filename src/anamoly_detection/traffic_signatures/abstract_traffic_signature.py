import re
import abc
from scapy.all import Packet
from scapy.layers import l2, inet, inet6

DefaultAllowedTraffic = {
    l2.Ether, l2.ARP, l2.Dot1AD, l2.Dot1Q, inet.IP, inet.ICMP, inet6.IPv6
}

def pull_layer(layer):
    """
    Pulls layer as a nice looking string, removes scapy class info
    :param layer: scapy layer object
    :return: str
    """
    class_desc = str(layer).split('.')
    return re.match(r"^[^']*", class_desc[len(class_desc) - 1]).group(0)

class AbstractTrafficSignature(abc.ABC):
    @abc.abstractmethod
    def __call__(self, packet: Packet):
        """

        :param packet:
        :return:
        """
        raise NotImplementedError
