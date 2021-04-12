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
        self.process_pcap_alert("port21.pcap")
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_111(self, mock_alert):
        # Plaintext data: Hello World
        self.process_pcap_alert("port111.pcap")
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_plaintext_benign(self, mock_alert):
        # Plaintext data: Hello World
        self.process_pcap_alert("plaintext.pcap")
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_credit_card1(self, mock_alert):
        # Plaintext data: Hello World, credit card=1234123412341234, Hello World
        self.process_pcap_alert("credit_card1.pcap")
        self.assertEqual(2, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_credit_card2(self, mock_alert):
        # Plaintext data: Hello World, credit card=1234-1234-1234-1234, Hello World
        self.process_pcap_alert("credit_card2.pcap")
        self.assertEqual(2, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_credit_card3(self, mock_alert):
        # Plaintext data: 1234-1234-1234-1234
        self.process_pcap_alert("credit_card3.pcap")
        self.assertEqual(2, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_credit_card_benign1(self, mock_alert):
        # Plaintext data: Hello World, not-a-credit-card=12-22-1234-1234-55, Hello World
        self.process_pcap_alert("credit_card_benign1.pcap")
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_credit_card_benign2(self, mock_alert):
        # Plaintext data: Hello World, 123456789012345678901234567890, Hello World
        self.process_pcap_alert("credit_card_benign2.pcap")
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_credit_card_benign3(self, mock_alert):
        # Plaintext data: 123456789012345678901234567890
        self.process_pcap_alert("credit_card_benign3.pcap")
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_ssn1(self, mock_alert):
        # Plaintext data: Hello World, 123-12-1234, Hello World
        self.process_pcap_alert("ssn1.pcap")
        self.assertEqual(2, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_ssn2(self, mock_alert):
        # Plaintext data: Hello World, 123121234, Hello World
        self.process_pcap_alert("ssn2.pcap")
        self.assertEqual(2, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_ssn3(self, mock_alert):
        # Plaintext data: 123121234
        self.process_pcap_alert("ssn3.pcap")
        self.assertEqual(2, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_ssn_benign(self, mock_alert):
        # Plaintext data:  Hello World, 12-12-1234, Hello World
        self.process_pcap_alert("ssn_benign.pcap")
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_email(self, mock_alert):
        # Plaintext data: Hello World, tinyHIPPO@fake.com, Hello World
        self.process_pcap_alert("email.pcap")
        self.assertEqual(2, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_ssn_email(self, mock_alert):
        # Plaintext data: Hello World, 123121234, Hello World, tinyHIPPO@fake.com, Hello World
        self.process_pcap_alert("ssn_email.pcap")
        self.assertEqual(3, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_keyword_one(self, mock_alert):
        # Plaintext data: Hello World, password, Hello World
        self.process_pcap_alert("keyword_one.pcap")
        self.assertEqual(2, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_keyword_multiple(self, mock_alert):
        # Plaintext data: Hello World, password, Hello World, e-mail, Hello World
        self.process_pcap_alert("keyword_multiple.pcap")
        self.assertEqual(3, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_port_80_email_keyword(self, mock_alert):
        # Plaintext data: Hello World, tinyHIPPO@fake.com, Hello World, password, Hello World
        self.process_pcap_alert("email_keyword.pcap")
        self.assertEqual(3, mock_alert.call_count)

    def process_pcap_alert(self, test_pcap_name):
        packets = rdpcap(str(Path(root_path_test_data + test_pcap_name).resolve()))
        packet_test = packets[0]
        self.packet_privacy_port(packet_test)

    def tearDown(self) -> None:
        pass

