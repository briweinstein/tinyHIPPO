import unittest
from scapy.all import rdpcap
from scapy.layers.inet import IP
from src.signature_detection.ip_signature import IPSignature
from pathlib import Path


class TestIPSignature(unittest.TestCase):
    def setUp(self) -> None:
        self.ip_signature = IPSignature("192.168.1.0/24")
        packets = rdpcap(str(Path("../test_data/test_packets.pcap").resolve()))
        self.src_malicious_ip_packet = packets[0]
        self.dst_malicious_ip_packet = packets[1]
        self.src_benign_ip_packet = packets[2]
        self.dst_benign_ip_packet = packets[3]
        self.src_malicious_ip_packet[IP].src = "62.210.205.141"
        self.dst_malicious_ip_packet[IP].dst = "5.188.62.140"
        self.src_benign_ip_packet[IP].src = "13.107.6.152"
        self.dst_benign_ip_packet[IP].dst = "150.171.32.1"

    def test_benign_ip(self):
        self.assertFalse(self.ip_signature(self.src_benign_ip_packet))
        self.assertFalse(self.ip_signature(self.dst_benign_ip_packet))

    def test_malicious_ip(self):
        self.assertTrue(self.ip_signature(self.src_malicious_ip_packet))
        self.assertTrue(self.ip_signature(self.dst_malicious_ip_packet))

    def tearDown(self) -> None:
        pass


if __name__ == '__main__':
    unittest.main()
