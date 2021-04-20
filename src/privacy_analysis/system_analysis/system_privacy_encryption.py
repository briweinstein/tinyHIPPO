#! /usr/bin/env python3
from src.privacy_analysis.system_analysis.system_privacy import SystemPrivacy
from src.privacy_analysis.system_analysis.helpers_analysis import get_file_contents
from src.dashboard.alerts.alert import Alert, AlertType, Severity


class SystemPrivacyEncryption(SystemPrivacy):
    """
    This privacy detection is called once on every startup of tinyHIPPO. It looks through the '/etc/config/wireless'
    file to determine if the router uses weak encryption algorithms and alerts on any that are found. This detection's
    alert will also recommend that the user enable WPA2 encryption as a best practice.
    """
    def __call__(self):
        # Define the weak encryption modes to alert on
        weak_encryption_modes = ["none'", "wep", "owe'",
                                 "psk'", "psk+", "psk-",
                                 "wpa'", "wpa+", "wpa-"]

        # Get the data from the file with the encryption information
        data = get_file_contents("/etc/config/wireless")
        if data is None:
            return

        # Check if any weak encryption modes are used on router
        for mode in weak_encryption_modes:
            if ("encryption '" + mode) in data:
                alert_obj = Alert(None, f"Weak encryption is in use. Switch to WPA2 from {mode}.", AlertType.PRIVACY,
                                  Severity.ALERT)
                alert_obj.alert()
