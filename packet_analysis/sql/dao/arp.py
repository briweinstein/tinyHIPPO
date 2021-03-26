from scapy.all import Packet
from ..dao.sqlObject import sqlObject
from ..dao.ethernet import Ethernet, table_sql as ethernet_table_sql

def table_sql() -> str:
    return ethernet_table_sql()

class ARP(sqlObject):
    def __init__(self, pkt: Packet):
        self.ether = Ethernet(pkt)

    def csv(self):
        return self.ether.csv()
