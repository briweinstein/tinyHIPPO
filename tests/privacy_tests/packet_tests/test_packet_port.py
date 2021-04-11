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
        # Plaintext data: Hello World
        self.process_pcap_alert("port21.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_111(self, mock_alert):
        # Plaintext data: Hello World
        self.process_pcap_alert("port111.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_plaintext_benign(self, mock_alert):
        # Plaintext data: Hello World
        self.process_pcap_alert("plaintext.pcap", mock_alert.assert_called_once)

    """"
    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_credit_card1(self, mock_alert):
        # Plaintext data: Hello World, credit card=1234123412341234, Hello World
        self.process_pcap_alert("credit_card1.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_credit_card2(self, mock_alert):
        # Plaintext data: Hello World, credit card=1234-1234-1234-1234, Hello World
        self.process_pcap_alert("credit_card2.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_credit_card_benign(self, mock_alert):
        # Plaintext data: Hello World, not-a-credit-card=12-22-1234-1234-55, Hello World
        self.process_pcap_alert("credit_card_benign.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_ssn1(self, mock_alert):
        # Plaintext data: Hello World, 123-12-1234, Hello World
        self.process_pcap_alert("ssn1.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_ssn2(self, mock_alert):
        # Plaintext data: Hello World, 123121234, Hello World
        self.process_pcap_alert("ssn2.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_ssn_benign(self, mock_alert):
        # Plaintext data:  Hello World, 12-12-1234, Hello World
        self.process_pcap_alert("ssn_benign.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_email(self, mock_alert):
        # Plaintext data: Hello World, tinyHIPPO@fake.com, Hello World
        self.process_pcap_alert("email.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_ssn_email(self, mock_alert):
        # Plaintext data: Hello World, 123121234, Hello World, tinyHIPPO@fake.com, Hello World
        self.process_pcap_alert("ssn_email.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_keyword_one(self, mock_alert):
        # Plaintext data: Hello World, password, Hello World
        self.process_pcap_alert("keyword_one.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_keyword_multiple(self, mock_alert):
        # Plaintext data: Hello World, password, Hello World, e-mail, Hello World
        self.process_pcap_alert("keyword_multiple.pcap", mock_alert.assert_called_once)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_email_keyword(self, mock_alert):
        # Plaintext data: Hello World, tinyHIPPO@fake.com, Hello World, password, Hello World
        self.process_pcap_alert("email_keyword.pcap", mock_alert.assert_called_once)
    """

    def process_pcap_alert(self, test_pcap_name, mock_alert_function):
        packets = rdpcap(str(Path(root_path_test_data + test_pcap_name).resolve()))
        packet_test = packets[0]
        self.packet_privacy_port(packet_test)
        mock_alert_function()

    def tearDown(self) -> None:
        pass


if __name__ == '__main__':
    unittest.main()
