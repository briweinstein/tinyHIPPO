#! /usr/bin/env python3
from src.privacy_analysis import SystemPrivacy
from src.privacy_analysis import get_file_contents


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
                # TODO: alert("Weak encryption is in use. Switch to WPA2 from " + mode + ".")
                print("Weak encryption found")
