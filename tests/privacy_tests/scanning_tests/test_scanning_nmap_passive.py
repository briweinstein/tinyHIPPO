import unittest
import unittest.mock as um
from src.privacy_analysis.scanning_analysis.scanning_privacy_nmap_passive import ScanningPrivacyNmapPassive


class TestScanningPrivacyNmapPassive(unittest.TestCase):
    """
    The nmap scanning file does two nmap scans. Due to limitations of mock, the second nmap scan will alert on every
    port in the return value. To account for this, the assertEqual in each test file subtracts the number of ports
    scanned. Also due to this, the second nmap scan cannot be tested explicitly, but its usage is similar enough
    to the first nmap scan.
    """
    def setUp(self) -> None:
        self.ip_to_mac = {"8.8.8.8": "AA:BB:CC:DD:EE"}

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("nmap.PortScanner.scan")
    def test_tcp_bad1(self, mock_nmap, mock_alert):
        ports_scanned = 2
        mock_nmap.return_value = {"scan": {"8.8.8.8": {"tcp": {22: {"state": "filtered"}, 7: {"state": "filtered"}}}}}
        ScanningPrivacyNmapPassive()(self.ip_to_mac)
        self.assertEqual(1, mock_alert.call_count - ports_scanned)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("nmap.PortScanner.scan")
    def test_tcp_bad2(self, mock_nmap, mock_alert):
        ports_scanned = 3
        mock_nmap.return_value = {"scan": {"8.8.8.8": {"tcp": {22: {"state": "filtered"}, 7: {"state": "filtered"},
                                                               23: {"state": "filtered"}}}}}
        ScanningPrivacyNmapPassive()(self.ip_to_mac)
        self.assertEqual(2, mock_alert.call_count - ports_scanned)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("nmap.PortScanner.scan")
    def test_tcp_severe(self, mock_nmap, mock_alert):
        ports_scanned = 1
        mock_nmap.return_value = {"scan": {"8.8.8.8": {"tcp": {21: {"state": "filtered"}}}}}
        ScanningPrivacyNmapPassive()(self.ip_to_mac)
        self.assertEqual(2, mock_alert.call_count - ports_scanned)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("nmap.PortScanner.scan")
    def test_tcp_good(self, mock_nmap, mock_alert):
        ports_scanned = 2
        mock_nmap.return_value = {"scan": {"8.8.8.8": {"tcp": {7: {"state": "filtered"}, 443: {"state": "filtered"}}}}}
        ScanningPrivacyNmapPassive()(self.ip_to_mac)
        self.assertEqual(0, mock_alert.call_count - ports_scanned)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("nmap.PortScanner.scan")
    def test_udp_bad1(self, mock_nmap, mock_alert):
        ports_scanned = 2
        mock_nmap.return_value = {"scan": {"8.8.8.8": {"udp": {22: {"state": "filtered"}, 7: {"state": "filtered"}}}}}
        ScanningPrivacyNmapPassive()(self.ip_to_mac)
        self.assertEqual(1, mock_alert.call_count - ports_scanned)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("nmap.PortScanner.scan")
    def test_udp_bad2(self, mock_nmap, mock_alert):
        ports_scanned = 3
        mock_nmap.return_value = {"scan": {"8.8.8.8": {"udp": {22: {"state": "filtered"}, 7: {"state": "filtered"},
                                                               23: {"state": "filtered"}}}}}
        ScanningPrivacyNmapPassive()(self.ip_to_mac)
        self.assertEqual(2, mock_alert.call_count - ports_scanned)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("nmap.PortScanner.scan")
    def test_udp_severe(self, mock_nmap, mock_alert):
        ports_scanned = 1
        mock_nmap.return_value = {"scan": {"8.8.8.8": {"tcp": {21: {"state": "filtered"}}}}}
        ScanningPrivacyNmapPassive()(self.ip_to_mac)
        self.assertEqual(2, mock_alert.call_count - ports_scanned)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("nmap.PortScanner.scan")
    def test_udp_good(self, mock_nmap, mock_alert):
        ports_scanned = 2
        mock_nmap.return_value = {"scan": {"8.8.8.8": {"udp": {7: {"state": "filtered"}, 443: {"state": "filtered"}}}}}
        ScanningPrivacyNmapPassive()(self.ip_to_mac)
        self.assertEqual(0, mock_alert.call_count - ports_scanned)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("nmap.PortScanner.scan")
    def test_tcp_udp_bad(self, mock_nmap, mock_alert):
        ports_scanned = 2
        mock_nmap.return_value = {"scan": {"8.8.8.8": {"tcp": {22: {"state": "filtered"}},
                                                       "udp": {23: {"state": "filtered"}}}}}
        ScanningPrivacyNmapPassive()(self.ip_to_mac)
        self.assertEqual(2, mock_alert.call_count - ports_scanned)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("nmap.PortScanner.scan")
    def test_tcp_udp_good(self, mock_nmap, mock_alert):
        ports_scanned = 2
        mock_nmap.return_value = {"scan": {"8.8.8.8": {"tcp": {7: {"state": "filtered"}},
                                                       "udp": {7: {"state": "filtered"}}}}}
        ScanningPrivacyNmapPassive()(self.ip_to_mac)
        self.assertEqual(0, mock_alert.call_count - ports_scanned)

    def tearDown(self) -> None:
        pass


if __name__ == '__main__':
    unittest.main()
