#! /usr/bin/env python3
from src.privacy_analysis.system_analysis.system_privacy import SystemPrivacy
from dashboard.alerts.alert import alert, ALERT_TYPE, SEVERITY
import os


# Check for package upgrades
class SystemPrivacyPackageUpgrades(SystemPrivacy):
    def __call__(self):
        upgradable = os.popen("opkg list-upgradable").read()
        if upgradable != "":
            alert_obj = alert("Packages are available for an update.", ALER_TYPE.PRIVACY, SEVERITY.INFO)
            alert_obj.alert()

