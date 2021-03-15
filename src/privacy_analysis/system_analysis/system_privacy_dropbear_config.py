#! /usr/bin/env python3
from src.privacy_analysis.system_analysis.system_privacy import SystemPrivacy
from src.privacy_analysis.system_analysis.helpers_analysis import get_file_contents


# Checks the dropbear configuration for root login and password login
class SystemPrivacyDropbearConfig(SystemPrivacy):
    def __init__(self):
        pass

    def __call__(self):
        print("thx")
        data = get_file_contents("/etc/config/dropbear")
        if (data is not None) and ("RootPasswordAuth 'on'" in data):
            # TODO: alert("Root user can login via ssh. Consider disabling this for security purposes.")
            print("Root user can login via ssh.")
        if "PasswordAuth 'on'" in data:
            # TODO: alert("Password login via ssh is allowed. Consider only allowing keypair login via ssh.")
            print("Password login via ssh is allowed.")

