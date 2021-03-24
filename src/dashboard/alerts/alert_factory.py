#! /usr/bin/env python3

from src.dashboard.alerts.abstract_alert import ALERT_TYPE, SEVERITY, Alert


class AlertFactory:
    def createAlert(self, alert_type: ALERT_TYPE, pkt=None, alert_description="", alert_severity=SEVERITY.INFO,
                    is_destination=False):
        if alert_type == ALERT_TYPE.IDS:
            return None  # Implement IDS_Alert
        elif alert_type == ALERT_TYPE.IDS:
            return None  # Implement PRIV_Alert
        else:
            raise NotImplemented
