import unittest
from src.database.db_connection import DBConnection
from src import run_config
from os import environ

from src.database.models import Alerts


class TestInsert(unittest.TestCase):
    """Tests insertion of objects into database tables using sqlalchemy"""

    def setUp(self) -> None:
        self.db_connection = DBConnection(run_config.db_file)

    def test_insert_alert(self):
        a = Alerts(alert_type='IDS', description='test', severity=1, mac_address='00:00:00:00:00', payload='foobar')
        a.insert_new()


if __name__ == '__main__':
    unittest.main()
