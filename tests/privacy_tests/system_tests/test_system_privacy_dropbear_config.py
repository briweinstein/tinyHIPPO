import unittest
import unittest.mock as um
from src.privacy_analysis.system_analysis.system_privacy_dropbear_config import SystemPrivacyDropbearConfig


class TestSystemPrivacyDropbearConfig(unittest.TestCase):
    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_dropbear_config_root_only(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\noption RootPasswordAuth 'on'\nGARBAGE "
                                                              "DATA\n")):
            SystemPrivacyDropbearConfig()()
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_dropbear_config_passwd_only(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\noption PasswordAuth 'on'\nGARBAGE DATA")):
            SystemPrivacyDropbearConfig()()
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_dropbear_config_root_and_passwd(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\noption PasswordAuth 'on'\nGARBAGE DATA\n"
                                                              "option RootPasswordAuth 'on'\nGARBAGE DATA")):
            SystemPrivacyDropbearConfig()()
        self.assertEqual(2, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_dropbear_config_good(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\noption PasswordAuth 'off'\nGARBAGE DATA\n"
                                                              "option RootPasswordAuth 'off'\nGARBAGE DATA")):
            SystemPrivacyDropbearConfig()()
        self.assertEqual(0, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_dropbear_config_empty(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA")):
            SystemPrivacyDropbearConfig()()
        self.assertEqual(0, mock_alert.call_count)


if __name__ == '__main__':
    unittest.main()
