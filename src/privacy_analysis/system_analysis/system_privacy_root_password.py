#! /usr/bin/env python3
from src.privacy_analysis.system_analysis import SystemPrivacy
from src.privacy_analysis.system_analysis import get_file_contents


# Check if a root password has been set
class SystemPrivacyRootPassword(SystemPrivacy):
    def __call__(self):
        data = get_file_contents("/etc/shadow")
        if (data is not None) and ("root::" in data):
            # TODO: alert("No root password set. Set a root password.")
            print("No root password set.")

