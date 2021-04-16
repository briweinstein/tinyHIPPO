import unittest
from src import db

from src.database.models import Alerts, AnomalyEquations, EmailInformation, DeviceInformation


class TestInsert(unittest.TestCase):
    """Tests insertion of objects into database tables using sqlalchemy"""

    def setUp(self) -> None:
        self.db = db
        self.db.create_session()
        self.alert = Alerts(alert_type='IDS', description='test', severity=1, mac_address='00:00:00:00:00',
                            payload='foobar')
        self.anamoly_eq = AnomalyEquations(average_equation="test", adjustment_equation="test")
        self.email_info = EmailInformation(recipient_addresses='test@email.com, foo@bar.com',
                                           sender_address='openwrt@alert.com',
                                           sender_email_password='super_secure_password',
                                           smtp_server='smtp.test.com')
        self.device_info = DeviceInformation(mac_address='00:00:00:00:00:00',
                                             name='test',
                                             ip_address='192.168.0.1')

    def test_insert_alert(self):
        Alerts.insert_new_object(self.alert)
        result = self.db.session.query(Alerts).filter(Alerts.description == 'test').first()
        self.assertEqual(self.alert, result)
        self.db.session.delete(result)

    def test_insert_anomaly_equation(self):
        AnomalyEquations.insert_new_object(self.anamoly_eq)
        result = self.db.session.query(AnomalyEquations).filter(AnomalyEquations.average_equation == "test").first()
        self.assertEqual(self.anamoly_eq, result)
        self.db.session.delete(result)

    def test_insert_email_information(self):
        EmailInformation.insert_new_object(self.email_info)
        result = self.db.session.query(EmailInformation).filter(
            EmailInformation.recipient_addresses == "test@email.com, foo@bar.com") \
            .first()
        self.assertEqual(self.email_info, result)
        self.db.session.delete(result)

    def test_insert_device_information(self):
        DeviceInformation.insert_new_object(self.device_info)
        result = self.db.session.query(DeviceInformation).filter(
            DeviceInformation.mac_address == "00:00:00:00:00:00") \
            .first()
        self.assertEqual(self.device_info, result)
        self.db.session.delete(result)

    def tearDown(self) -> None:
        self.db.session.commit()

    if __name__ == '__main__':
        unittest.main()
