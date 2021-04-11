import unittest
import unittest.mock as um
from pathlib import Path
from scapy.all import rdpcap
from src.privacy_analysis.packet_analysis.packet_privacy_port import PacketPrivacyPort

root_path_test_data = "../../test_data/"


class TestIPSignature(unittest.TestCase):
    def setUp(self) -> None:
        self.packet_privacy_port = PacketPrivacyPort()

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_21(self, mock_alert):
        packets = rdpcap(str(Path(root_path_test_data + "port21.pcap").resolve()))
        packet_test = packets[0]
        self.packet_privacy_port(packet_test)
        mock_alert.assert_called_once()

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_111(self, mock_alert):
        packets = rdpcap(str(Path(root_path_test_data + "port111.pcap").resolve()))
        packet_test = packets[0]
        self.packet_privacy_port(packet_test)
        mock_alert.assert_called_once()

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_benign_plaintext(self, mock_alert):
        packets = rdpcap(str(Path(root_path_test_data + "plaintext.pcap").resolve()))
        packet_test = packets[0]
        self.packet_privacy_port(packet_test)
        mock_alert.assert_called_once()

    def tearDown(self) -> None:
        pass


if __name__ == '__main__':
    unittest.main()
