from scapy.all import Packet
from ..dao.sqlObject import sqlObject

def table_sql() -> str:
    return """id       INTEGER     PRIMARY KEY AUTOINCREMENT
                                   UNIQUE
                                   NOT NULL,
              time     DECIMAL     NOT NULL,
              hour     INTEGER     NOT NULL,
              pkt_len  INTEGER     NOT NULL,
              src_mac  STRING (40) NOT NULL,
              dst_mac  STRING (40) NOT NULL"""

class Ethernet(sqlObject):
    def __init__(self, pkt: Packet):
        self.time = pkt.time
        self.hour = (int(self.time) % 86400) // 3600
        self.length = len(pkt)
        self.src_mac = pkt["Ethernet"].src
        self.dst_mac = pkt["Ethernet"].dst

    def csv(self):
        # Always include the 'None' for the first item in order to all the auto-increment ID to work
        return [None, str(self.time), self.hour, self.length, str(self.src_mac), str(self.dst_mac)]
