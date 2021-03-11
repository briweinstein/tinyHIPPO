import abc
from scapy.all import Packet


class Signature(abc.ABC):
    """
    This abstract base class represents a single signature to be checked against packets in our IoT IDS
    """
    @property
    def msg(self):
        return type(self).__name__

    @abc.abstractmethod
    def __call__(self, packet: Packet) -> bool:
        raise NotImplementedError
