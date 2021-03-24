import unittest
from scapy.all import rdpcap
from pathlib import Path
from src.dashboard.alerts.alert import Alert, ALERT_TYPE, SEVERITY
from scapy.layers.inet import Ether, IP
from src import run_config
from unittest.mock import MagicMock
from unittest.mock import patch
from scapy.packet import Packet
from src.signature_detection.signature_detector import SignatureDetector
from src.signature_detection.signature import Signature
from src.signature_detection.ip_signature import IPSignature
from src.signature_detection.mac_address_signature import MACAddressSignature


class TestMainLoop(unittest.TestCase):
    def setUp(self) -> None:
        packets = rdpcap(str(Path("test_data/test_tcpdump2.pcap").resolve()))
        self.src_malicious_ip_packet = packets[0]
        self.dst_malicious_ip_packet = packets[1]
        self.src_malicious_ip_packet[IP].src = "62.210.205.141"
        self.dst_malicious_ip_packet[IP].dst = "5.188.62.140"
        self.ids_signatures = [IPSignature("192.168.1.0/24"), MACAddressSignature()]
        self.signature_detector = SignatureDetector(self.ids_signatures)

    def test_pull_and_validate_addrs(self):
        return True

    def test_packet_parse(self):
        self.assertTrue(self.packet_parse(self.dst_malicious_ip_packet))
        self.assertTrue(self.packet_parse(self.src_malicious_ip_packet))

    def packet_parse(self, packet):
        with patch.object(Alert, 'alert', return_value=True) as mock_alert:
            triggered_rules = self.signature_detector.check_signatures(packet)
            if len(triggered_rules) > 0:
                for triggered_rule in triggered_rules:
                    is_dst = packet[Ether].src in run_config.mac_addrs
                    alert_object = Alert(packet, triggered_rule.msg, ALERT_TYPE.IDS, SEVERITY.ALERT, is_dst)
                    return alert_object.alert()

    def tearDown(self) -> None:
        pass


if __name__ == '__main__':
    unittest.main()
