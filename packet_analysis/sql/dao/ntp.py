from scapy.all import Packet
from ..dao.sqlObject import sqlObject
from ..dao.udp import UDP, table_sql as udp_table_sql

def table_sql() -> str:
    return udp_table_sql() + \
           """,
              ref_id    STRING (64) NOT NULL,
              id        STRING (64) NOT NULL,
              npt_ver   STRING (40) NOT NULL"""

class NTPHeader(sqlObject):
    def __init__(self, pkt: Packet):
        self.udp = UDP(pkt)
        self.ref_id = pkt["NTPHeader"].ref_id
        self.id = pkt["NTPHeader"].id
        self.version = pkt["NTPHeader"].version

    def csv(self):
        return self.udp.csv() + [str(self.ref_id), str(self.id), str(self.version)]
