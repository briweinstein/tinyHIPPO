from scapy.all import Packet
from ..dao.sqlObject import sqlObject
from ..dao.ip import IP, table_sql as ip_table_sql


def table_sql() -> str:
    return ip_table_sql() + \
           """,
              src_port STRING (40) NOT NULL,
              dst_port STRING (40) NOT NULL,
              upd_len  INTEGER     NOT NULL"""


class UDP(sqlObject):
    def __init__(self, pkt: Packet):
        self.ip = IP(pkt)
        self.src_port = pkt["UDP"].sport
        self.dst_port = pkt["UDP"].dport
        self.length = pkt["UDP"].len

    def csv(self):
        return self.ip.csv() + [str(self.src_port), str(self.dst_port), self.length]
