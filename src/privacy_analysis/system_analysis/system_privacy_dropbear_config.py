from src.privacy_analysis.system_analysis.system_privacy import SystemPrivacy
from src.privacy_analysis.system_analysis.helpers_analysis import get_file_contents
from src.dashboard.alerts.alert import Alert, AlertType, Severity


class SystemPrivacyDropbearConfig(SystemPrivacy):
    """
    This privacy detection is called once on every startup of tinyHIPPO. It looks through the '/etc/config/dropbear'
    file to analyze dropbear configurations and alert on privacy misconfigurations. Dropbear handles remote connections
    to the router, so it is important that it is configured correctly. This detection checks the configuration for root
    login and password login and will alert on both. Best practice is to disallow root login and use ssh keys instead
    of a password.
    """

    def __call__(self):
        # Get the data from the file with the dropbear configuration
        data = get_file_contents("/etc/config/dropbear")

        # Alert if root login is allowed
        if (data is not None) and ("option RootPasswordAuth 'on'" in data):
            alert_root_login = Alert(None,
                                     "Root user can login via ssh. Consider disabling this for security purposes.",
                                     AlertType.PRIVACY, Severity.INFO)
            alert_root_login.alert()

        # Alert if password login is allowed
        if (data is not None) and ("option PasswordAuth 'on'" in data):
            alert_general_login = Alert(None,
                                        "Password login via ssh is allowed. Consider only allowing keypair login via "
                                        "ssh.", AlertType.PRIVACY, Severity.INFO)
            alert_general_login.alert()
