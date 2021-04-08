import unittest
import unittest.mock as um
from src.privacy_analysis.system_analysis.system_privacy_encryption import SystemPrivacyEncryption
from tests.privacy_tests.system_tests.system_helper import assert_failed


class TestSystemPrivacyEncryption(unittest.TestCase):
    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_encryption_one_weak(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\noption encryption 'wep-shared'\nGARBAGE "
                                                              "DATA\n")):
            SystemPrivacyEncryption()()
        mock_alert.assert_called_once()

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_encryption_multiple_weak(self, mock_alert):
        result = assert_failed("GARBAGE DATA\noption encryption 'wep-shared'\nGARBAGE DATA\noption encryption 'none'\n"
                               "option encryption 'wpa-shared'\nGARBAGE DATA\nGARBAGE DATA\n",
                               SystemPrivacyEncryption(), mock_alert.assert_called_once)
        self.assertTrue(result)
        mock_alert.assert_called()

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_encryption_good(self, mock_alert):
        result = assert_failed("GARBAGE DATA\noption encryption 'psk2'\nGARBAGE DATA\nGARBAGE DATA\nGARBAGE DATA\n",
                               SystemPrivacyEncryption(), mock_alert.assert_called)
        self.assertTrue(result)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_encryption_empty(self, mock_alert):
        result = assert_failed("GARBAGE DATA", SystemPrivacyEncryption(), mock_alert.assert_called)
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
