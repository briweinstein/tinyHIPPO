from scapy.all import Packet
from packet_analysis.sql.dao.sqlObject import sqlObject
from packet_analysis.sql.dao.ethernet import Ethernet


class IP(sqlObject):
    """
    Object holding the information for an IP header
    """

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

    @staticmethod
    def table_sql() -> str:
        """
        Constructs the necessary parameters for the table building as a string
        :return: str
        """
        return Ethernet.table_sql() + \
               """,
                  src_ip   STRING (64) NOT NULL,
                  dst_ip   STRING (64) NOT NULL,
                  v6       BOOLEAN     NOT NULL"""

    def csv(self):
        """
        Creates a list of the arguments required for an INSERT statement
        :return: list
        """
        return self.ether.csv() + [str(self.src_ip), str(self.dst_ip), str(self.v6)]
