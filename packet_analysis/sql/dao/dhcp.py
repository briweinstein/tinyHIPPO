from scapy.all import Packet
from ..dao.sqlObject import sqlObject
from ..dao.udp import UDP, table_sql as udp_table_sql

def table_sql() -> str:
    return udp_table_sql() + \
           """,
              client_ip    STRING (40) NOT NULL,
              assigned_ip  STRING (40) NOT NULL,
              server_ip    STRING (40) NOT NULL,
              client_mac   STRING (40) NOT NULL,
              options      TEXT        NOT NULL"""


class BOOTP(sqlObject):
    def __init__(self, pkt: Packet):
        self.udp = UDP(pkt)
        self.client_ip = pkt["BOOTP"].ciaddr
        self.assigned_ip = pkt["BOOTP"].yiaddr
        self.server_ip = pkt["BOOTP"].siaddr
        self.client_mac = pkt["BOOTP"].chaddr

    def csv(self):
        return self.udp.csv() + [str(self.client_ip), str(self.assigned_ip), str(self.server_ip), str(self.client_mac)]


class DHCP(sqlObject):
    def __init__(self, pkt: Packet):
        self.bootp = BOOTP(pkt)
        self.options = pkt["DHCP"].options

    def csv(self):
        return self.bootp.csv() + [str(self.options)]

