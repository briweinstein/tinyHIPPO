from typing import List
from scapy.all import Packet
from src.signature_detection.signature import Signature


class SignatureDetector:
    """
    This class defines the methods that must be defined for Signature Detection for an IoT device to be supported
    """

    def __init__(self, rules: List[Signature]):
        """
        Constructor for this signature detector
        :param rules: A list of Signatures for this signature detector to check packets against
        """
        self.rules = rules

    def check_signatures(self, packet: Packet) -> List[Signature]:
        """
        Checks the given packet against all defined signatures
        :param packet: Scapy packet to check signatures against
        :return: List of triggered signatures
        """
        return [rule for rule in self.rules if rule(packet)]
