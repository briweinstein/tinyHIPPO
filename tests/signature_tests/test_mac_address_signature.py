import unittest
import pathlib
from scapy.all import rdpcap
from scapy.layers.inet import Ether
from src.signature_detection.mac_address_signature import MACAddressSignature


class TestMACAddressSignature(unittest.TestCase):
    def setUp(self) -> None:
        self.mac_signature = MACAddressSignature()
        packets = rdpcap(str(pathlib.Path("../test_data/test_packets.pcap").resolve()))
        self.src_spoofed_mac_packet = packets[0]
        self.src_spoofed_mac_packet[Ether].src = "CC:43:65:61:39:D9"
        self.src_benign_mac_packet = packets[1]
        self.src_benign_mac_packet[Ether].src = "A0:9F:10:1B:D7:05"

    def test_benign_mac(self):
        self.assertFalse(self.mac_signature(self.src_benign_mac_packet))

    def test_spoofed_mac(self):
        self.assertTrue(self.mac_signature(self.src_spoofed_mac_packet))

    def tearDown(self) -> None:
        pass


if __name__ == '__main__':
    unittest.main()
