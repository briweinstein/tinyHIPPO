#! /usr/bin/env python3
from src.privacy_analysis.system_analysis.system_privacy import SystemPrivacy
from src.dashboard.alerts.alert import Alert, AlertType, Severity
import os


class SystemPrivacyPackageUpgrades(SystemPrivacy):
    """
    This privacy detection is called once on every startup of tinyHIPPO. It looks for any package upgrades that are
    available, reminding the user to upgrade their packages to the latest version if possible. This will minimize
    router compromise through vulnerable packages.
    """
    def __call__(self):
        # Determine if there are any packages that can be upgraded
        upgradable = os.popen("opkg list-upgradable").read()

        # Alert if any upgradable packages are found
        if upgradable != "":
            alert_obj = Alert(None, "Packages are available for an update.", AlertType.PRIVACY, Severity.INFO)
            alert_obj.alert()
