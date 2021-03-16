#! /usr/bin/env python3
from src.privacy_analysis.system_analysis.system_privacy import SystemPrivacy
from src.privacy_analysis.system_analysis.helpers_analysis import get_file_contents
from dashboard.alerts.alert import alert, ALERT_TYPE, SEVERITY

# Validate the router encryption type is not weak
class SystemPrivacyEncryption(SystemPrivacy):
    def __call__(self):
        weak_encryption_modes = ["none'", "wep", "owe'",
                                 "psk'", "psk+", "psk-",
                                 "wpa'", "wpa+", "wpa-"]
        data = get_file_contents("/etc/config/wireless")
        if data is None:
            return
        for mode in weak_encryption_modes:
            if ("encryption '" + mode) in data:
                print("Weak encryption found")
                alert_obj = alert("Weak encryption is in use. Switch to WPA2 from " + mode + ".", ALERT_TYPE.PRIVACY, SEVERITY.ALERT)
                alert_obj.alert()
                print("Weak encryption alerted")


