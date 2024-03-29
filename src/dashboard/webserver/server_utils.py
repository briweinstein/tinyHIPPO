import ipaddress
import subprocess
from typing import List
import re
from dataclasses import dataclass
from src.database.models import Alerts, DeviceInformation
from src.database.db_connection import DBConnection
from src import run_config
from pathlib import Path


@dataclass
class NeighboringDevice:
    ip: ipaddress.ip_address
    mac: str
    interface: str


def get_db(db_file: Path):
    try:
        db = DBConnection(db_file)
        db.create_session()
        return db
    except Exception as e:
        run_config.log_event.info(e)


def get_neighboring_devices() -> List[NeighboringDevice]:
    """
    Retrieves a list of all neighboring devices and returns them as a dictionary
    :return: List of NeighboringDevices
    """
    regex = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s[\w\d]+\s([\w\d-]+).*((?:[0-9a-fA-F]:?){12})'
    arp_results = subprocess.getoutput('ip neigh')
    neighboring_devices = [NeighboringDevice(result[0], result[2], result[1]) for result in
                           re.findall(regex, arp_results)]
    return neighboring_devices


def get_alerts(alert_type: str, connection, limit_num: int) -> List[Alerts]:
    """
    Returns all alerts from the database matching the given alert type ordered by timestamp in descending order
    :param alert_type: Alert type to filter by
    :param limit_num: Number of alerts to return
    :return: Alerts from the database matching the given alert_type
    """
    query = connection.session.query(Alerts). \
        filter(Alerts.alert_type == alert_type). \
        order_by(Alerts.timestamp.desc())
    if limit_num != 0:
        query = query.limit(limit_num)
    return query.all()
