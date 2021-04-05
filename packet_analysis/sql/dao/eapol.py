from scapy.all import Packet
from ..dao.sqlObject import sqlObject
from ..dao.ethernet import Ethernet, table_sql as ethernet_table_sql


def table_sql() -> str:
    return ethernet_table_sql() + \
           """,
              eapol_ver  STRING (40) NOT NULL,
              type       STRING (40) NOT NULL,
              eapol_len  INTEGER     NOT NULL"""


class EAPOL(sqlObject):
    def __init__(self, pkt: Packet):
        self.ether = Ethernet(pkt)
        self.version = pkt["EAPOL"].version
        self.type = pkt["EAPOL"].type
        self.length = pkt["EAPOL"].len

    def csv(self):
        return self.ether.csv() + [str(self.version), str(self.type), str(self.length)]
