from scapy.all import Packet
from packet_analysis.sql.dao.sqlObject import sqlObject
from packet_analysis.sql.dao.ip import IP, table_sql as ip_table_sql


def table_sql() -> str:
    """
    Constructs the necessary parameters for the table building as a string
    :return: str
    """
    return ip_table_sql() + \
           """,
              src_port STRING (40) NOT NULL,
              dst_port STRING (40) NOT NULL,
              seq      INTEGER     NOT NULL"""


class TCP(sqlObject):
    """
    Object holding the information for an TCP segment header
    """

    def __init__(self, pkt: Packet):
        self.ip = IP(pkt)
        self.src_port = pkt["TCP"].sport
        self.dst_port = pkt["TCP"].dport
        self.seq = pkt["TCP"].seq

    def csv(self):
        """
        Creates a list of the arguments required for an INSERT statement
        :return: list
        """
        return self.ip.csv() + [str(self.src_port), str(self.dst_port), self.seq]
