#! /usr/bin/env python3
import abc
from scapy.all import Packet


class PacketPrivacy(abc.ABC):
    """
    This abstract base class represents a single privacy rule to be checked against packets in our IoT Privacy Protection System
    """

    @property
    def msg(self):
        return type(self).__name__

    @abc.abstractmethod
    def __call__(self, packet: Packet) -> None:
        raise NotImplementedError
