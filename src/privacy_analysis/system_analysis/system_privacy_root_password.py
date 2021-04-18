#! /usr/bin/env python3
from src.privacy_analysis.system_analysis.system_privacy import SystemPrivacy
from src.privacy_analysis.system_analysis.helpers_analysis import get_file_contents
from src.dashboard.alerts.alert import Alert, AlertType, Severity


class SystemPrivacyRootPassword(SystemPrivacy):
    """
    This privacy detection is called once on every startup of tinyHIPPO. It looks through the '/etc/shadow' file to
    determine if a root password has been set, and alerts if one has not been. Strong passwords should be set for users
    on the router, especially one as privileged as root.
    """
    def __call__(self):
        # Get the data from the file with the password hashes
        data = get_file_contents("/etc/shadow")

        # Alert if there is no password hash for the root user
        if (data is not None) and ("root::" in data):
            alert_obj = Alert(None, "No password is set for the root user, which should be done immediately.",
                              AlertType.PRIVACY, Severity.ALERT)
            alert_obj.alert()
