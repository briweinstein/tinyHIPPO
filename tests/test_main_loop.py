import unittest
from scapy.all import rdpcap
from pathlib import Path
from scapy.layers.inet import IP
from unittest.mock import patch

from src.database.models import DeviceInformation
from src.signature_detection.signature_detector import SignatureDetector
from src.signature_detection.ip_signature import IPSignature
from src.signature_detection.mac_address_signature import MACAddressSignature
from tiny_hippo_run import packet_parse


class TestMainLoop(unittest.TestCase):
    def setUp(self) -> None:
        packets = rdpcap(str(Path("test_data/test_packets.pcap").resolve()))
        self.src_malicious_ip_packet = packets[0]
        self.dst_malicious_ip_packet = packets[1]
        self.src_malicious_ip_packet[IP].src = "62.210.205.141"
        self.dst_malicious_ip_packet[IP].dst = "5.188.62.140"
        self.ids_signatures = [IPSignature("192.168.1.0/24"), MACAddressSignature()]
        self.signature_detector = SignatureDetector(self.ids_signatures)

    @unittest.mock.patch("src.dashboard.alerts.alert.Alert.alert", return_value=True)
    @unittest.mock.patch("src.privacy_analysis.packet_analysis.packet_privacy_port.PacketPrivacyPort.__call__",
                         return_value=True)
    def test_packet_parse(self, mock_privacy, mock_alert):
        packet_parse(self.src_malicious_ip_packet)
        packet_parse(self.dst_malicious_ip_packet)
        self.assertEqual(3, mock_alert.call_count)

    def tearDown(self) -> None:
        pass


if __name__ == '__main__':
    unittest.main()
