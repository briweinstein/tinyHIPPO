#! /usr/bin/env python3
from src.privacy_analysis.system_analysis.system_privacy import SystemPrivacy
from src.privacy_analysis.system_analysis.helpers_analysis import get_file_contents
from dashboard.alerts.alert import alert, ALERT_TYPE, SEVERITY


# Check if a root password has been set
class SystemPrivacyRootPassword(SystemPrivacy):
    def __call__(self):
        data = get_file_contents("/etc/shadow")
        if (data is not None) and ("root::" in data):
            alert_obj = alert("No root password set. Set a root password.", ALERT_TYPE.PRIVACY, SEVERITY.ALERT)
            alert_obj.alert()
