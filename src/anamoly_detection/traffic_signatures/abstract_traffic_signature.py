import re
import abc
from scapy.all import Packet


class AbstractTrafficSignature(abc.ABC):
    @abc.abstractmethod
    def __call__(self, packet: Packet):
        """
        Function call for signature object, runs signature rules on packet
        :param packet: Packet object being analyzed
        :return: None
        """
        raise NotImplementedError
