import unittest
import unittest.mock as um
from src.privacy_analysis.system_analysis.system_privacy_dropbear_config import SystemPrivacyDropbearConfig


class TestSystemPrivacyDropbearConfig(unittest.TestCase):

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_dropbear_config_root_only(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\noption RootPasswordAuth 'on'\nGARBAGE "
                                                              "DATA\n")):
            SystemPrivacyDropbearConfig()()
        mock_alert.assert_called_once()

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_dropbear_config_passwd_only(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\noption PasswordAuth 'on'\nGARBAGE DATA")):
            SystemPrivacyDropbearConfig()()
        mock_alert.assert_called_once()

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_dropbear_config_root_and_passwd(self, mock_alert):
        with um.patch("builtins.open", um.mock_open(read_data="GARBAGE DATA\noption PasswordAuth 'on'\nGARBAGE "
                                                              "DATA\noption RootPasswordAuth 'on'\nGARBAGE DATA")):
            SystemPrivacyDropbearConfig()()
        mock_alert.assert_called()
        called_once = False
        try:
            mock_alert.assert_called_once()
            called_once = True
        except:
            self.assertTrue(True)
        self.assertFalse(called_once)

if __name__ == '__main__':
    unittest.main()
