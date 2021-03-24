#! /usr/bin/env python3
from src.privacy_analysis.system_analysis.system_privacy import SystemPrivacy
from src.privacy_analysis.system_analysis.helpers_analysis import get_file_contents
from src.dashboard.alerts.alert import Alert, ALERT_TYPE, SEVERITY


# Checks the dropbear configuration for root login and password login
class SystemPrivacyDropbearConfig(SystemPrivacy):
    def __call__(self):
        data = get_file_contents("/etc/config/dropbear")
        if (data is not None) and ("RootPasswordAuth 'on'" in data):
            alert_root_login = Alert(None,"Root user can login via ssh. Consider disabling this for security purposes.",
                                     ALERT_TYPE.PRIVACY, SEVERITY.INFO)
            alert_root_login.alert()
        if "PasswordAuth 'on'" in data:
            alert_general_login = Alert(None,
                "Password login via ssh is allowed. Consider only allowing keypair login via ssh.", ALERT_TYPE.PRIVACY,
                SEVERITY.INFO)
            alert_general_login.alert()
