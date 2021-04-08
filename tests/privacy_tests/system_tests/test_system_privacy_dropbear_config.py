import unittest
import unittest.mock as um
from src.privacy_analysis.system_analysis.system_privacy_dropbear_config import SystemPrivacyDropbearConfig
from tests.privacy_tests.system_tests.system_helper import assert_failed


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
        result = assert_failed("GARBAGE DATA\noption PasswordAuth 'on'\nGARBAGE DATA\noption RootPasswordAuth 'on'\n"
                               "GARBAGE DATA", SystemPrivacyDropbearConfig(), mock_alert.assert_called_once)
        self.assertTrue(result)
        mock_alert.assert_called()

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_dropbear_config_good(self, mock_alert):
        result = assert_failed("GARBAGE DATA\noption PasswordAuth 'off'\nGARBAGE DATA\noption RootPasswordAuth 'off'\n"
                               "GARBAGE DATA", SystemPrivacyDropbearConfig(), mock_alert.assert_called)
        self.assertTrue(result)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_dropbear_config_empty(self, mock_alert):
        result = assert_failed("GARBAGE DATA", SystemPrivacyDropbearConfig(), mock_alert.assert_called)
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
