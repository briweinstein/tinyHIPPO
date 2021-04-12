import unittest
import unittest.mock as um
from src.privacy_analysis.system_analysis.system_privacy_encryption import SystemPrivacyEncryption


class TestSystemPrivacyEncryption(unittest.TestCase):
    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_encryption_one_weak(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\noption encryption 'wep-shared'\nGARBAGE "
                                                              "DATA\n")):
            SystemPrivacyEncryption()()
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_encryption_multiple_weak(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\noption encryption 'wep-shared'\n"
                                                              "GARBAGE DATA\noption encryption 'none'\noption "
                                                              "encryption 'wpa-shared'\nGARBAGE DATA\nGARBAGE DATA\n")):
            SystemPrivacyEncryption()()
        self.assertEqual(3, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_encryption_good(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\noption encryption 'psk2'\nGARBAGE DATA\n"
                                                              "GARBAGE DATA\nGARBAGE DATA\n")):
            SystemPrivacyEncryption()()
        self.assertEqual(0, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_encryption_empty(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA")):
            SystemPrivacyEncryption()()
        self.assertEqual(0, mock_alert.call_count)

