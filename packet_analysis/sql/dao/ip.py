from scapy.all import Packet
from packet_analysis.sql.dao.sqlObject import sqlObject
from packet_analysis.sql.dao.ethernet import Ethernet, table_sql as ethernet_table_sql


def table_sql() -> str:
    return ethernet_table_sql() + \
           """,
              src_ip   STRING (64) NOT NULL,
              dst_ip   STRING (64) NOT NULL,
              v6       BOOLEAN     NOT NULL"""

class IP(sqlObject):
    def __init__(self, pkt: Packet):
        self.ether = Ethernet(pkt)
        if "IP" in pkt:
            self.v6 = False
            key = "IP"
        else:
            self.v6 = True
            key = "IPv6"

        self.src_ip = pkt[key].src
        self.dst_ip = pkt[key].dst

    def csv(self):
        return self.ether.csv() + [str(self.src_ip), str(self.dst_ip), str(self.v6)]
