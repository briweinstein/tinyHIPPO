#! /usr/bin/env python3
from src.privacy_analysis.system_analysis.system_privacy import SystemPrivacy
import os


# Check for package upgrades
class SystemPrivacyPackageUpgrades(SystemPrivacy):
    def __call__(self):
        upgradable = os.popen("opkg list-upgradable").read()
        if upgradable != "":
            # TODO: alert("Packages are available for an update.")
            print("Package update found.")

