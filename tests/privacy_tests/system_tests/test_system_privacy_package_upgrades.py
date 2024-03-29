import unittest
import unittest.mock as um
import tempfile
from src.privacy_analysis.system_analysis.system_privacy_package_upgrades import SystemPrivacyPackageUpgrades


# Getting a "ResourceWarning: unclosed file" warning, but this is all kosher according to the docs and examples
class TestSystemPrivacyEncryption(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_stdout = tempfile.TemporaryFile()

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("subprocess.Popen")
    def test_package_upgrades_available(self, mock_popen, mock_alert):
        self.mock_stdout.write(b'HELLO')
        self.mock_stdout.seek(0)
        mock_popen.return_value.stdout = self.mock_stdout
        SystemPrivacyPackageUpgrades()()
        mock_popen.return_value.stdout.close()

        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    @um.patch("subprocess.Popen")
    def test_package_upgrades_absent(self, mock_popen, mock_alert):
        self.mock_stdout.write(b'')
        self.mock_stdout.seek(0)
        mock_popen.return_value.stdout = self.mock_stdout
        SystemPrivacyPackageUpgrades()()
        mock_popen.return_value.stdout.close()

        self.assertEqual(0, mock_alert.call_count)

    def tearDown(self) -> None:
        self.mock_stdout.close()


# Source:
# https://blog.samuel.domains/blog/programming/how-to-mock-stdout-runtime-attribute-of-subprocess-popen-python

