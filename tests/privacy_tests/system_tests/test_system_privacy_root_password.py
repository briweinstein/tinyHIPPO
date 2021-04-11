import unittest
import unittest.mock as um
from src.privacy_analysis.system_analysis.system_privacy_root_password import SystemPrivacyRootPassword


class TestSystemPrivacyEncryption(unittest.TestCase):
    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_root_password_empty(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\nroot::\nGARBAGE DATA\n")):
            SystemPrivacyRootPassword()()
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_root_password_exists(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\nroot:PASSWORD_HASH_HERE:\nGARBAGE DATA\n")):
            SystemPrivacyRootPassword()()
        self.assertEqual(0, mock_alert.call_count)


if __name__ == '__main__':
    unittest.main()
