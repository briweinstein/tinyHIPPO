import unittest
import unittest.mock as um
from src.privacy_analysis.scanning_analysis.scanning_privacy_nmap_passive import ScanningPrivacyNmapPassive


class TestScanningPrivacyNmapPassive(unittest.TestCase):
    def setUp(self) -> None:
        self.ip_to_mac = {"8.8.8.8": "AA:BB:CC:DD:EE"}

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("nmap.PortScanner.scan")
    def test_nmap(self, mock_nmap, mock_alert):
        mock_nmap.return_value = {"scan": {"1.1.1.1": {"tcp": {22: {"state": "filtered"}}}}}
        ScanningPrivacyNmapPassive()(self.ip_to_mac)
        mock_alert.assert_called_once()

    def tearDown(self) -> None:
        pass


if __name__ == '__main__':
    unittest.main()
