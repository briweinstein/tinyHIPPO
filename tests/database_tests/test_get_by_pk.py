import unittest
from src import db
from src.database.models import Alerts, AnomalyEquations, EmailInformation, DeviceInformation


class TestGetByPk(unittest.TestCase):
    """Tests retrieval function on models using SQLAlchemy"""
    def setUp(self) -> None:
        self.db = db
        self.alert = Alerts(alert_type='IDS', description='test', severity=1, mac_address='00:00:00:00:00',
                            payload='foobar')
        self.anamoly_eq = AnomalyEquations(average_equation="test", adjustment_equation="test")
        self.email_info = EmailInformation(recipient_addresses='test@email.com, foo@bar.com',
                                           sender_address='openwrt@alert.com',
                                           sender_email_password='super_secure_password',
                                           smtp_server='smtp.test.com')
        self.device_info = DeviceInformation(mac_address='00:00:00:00:00:00',
                                             device_name='test',
                                             device_ip_address='192.168.0.1')

    def test_get_alert_id(self):
        Alerts.insert_new_object(self.alert)
        result = Alerts.get_by_pk(Alerts.id, self.alert.id)
        self.assertEqual(self.alert, result)
        self.db.session.delete(result)

    def test_get_anomaly_equations_id(self):
        AnomalyEquations.insert_new_object(self.anamoly_eq)
        result = AnomalyEquations.get_by_pk(AnomalyEquations.id, self.anamoly_eq.id)
        self.assertEqual(self.anamoly_eq, result)
        self.db.session.delete(result)

    def test_get_email_information_id(self):
        EmailInformation.insert_new_object(self.email_info)
        result = EmailInformation.get_by_pk(EmailInformation.id, self.email_info.id)
        self.assertEqual(self.email_info, result)
        self.db.session.delete(result)

    def test_get_device_information_id(self):
        DeviceInformation.insert_new_object(self.device_info)
        result = DeviceInformation.get_by_pk(DeviceInformation.mac_address, self.device_info.mac_address)
        self.assertEqual(self.device_info, result)
        self.db.session.delete(result)

    def tearDown(self) -> None:
        self.db.session.commit()


if __name__ == '__main__':
    unittest.main()
