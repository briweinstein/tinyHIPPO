#! /usr/bin/env python3
from src.privacy_analysis.system_analysis.system_privacy import SystemPrivacy
from src.dashboard.alerts.alert import Alert, AlertType, Severity
import os


# Check for package upgrades
class SystemPrivacyPackageUpgrades(SystemPrivacy):
    def __call__(self):
        upgradable = os.popen("opkg list-upgradable").read()
        if upgradable != "":
            alert_obj = Alert(None, "Packages are available for an update.", AlertType.PRIVACY, Severity.INFO)
            alert_obj.alert()
