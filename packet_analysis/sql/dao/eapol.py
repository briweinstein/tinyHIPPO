from scapy.all import Packet
from packet_analysis.sql.dao.sqlObject import sqlObject
from packet_analysis.sql.dao.ethernet import Ethernet, table_sql as ethernet_table_sql


def table_sql() -> str:
    """
    Constructs the necessary parameters for the table building as a string
    :return: str
    """
    return ethernet_table_sql() + \
           """,
              eapol_ver  STRING (40) NOT NULL,
              type       STRING (40) NOT NULL,
              eapol_len  INTEGER     NOT NULL"""


class EAPOL(sqlObject):
    """
     Object representing the information for the EAPOL information of a packet
    """
    def __init__(self, pkt: Packet):
        self.ether = Ethernet(pkt)
        self.version = pkt["EAPOL"].version
        self.type = pkt["EAPOL"].type
        self.length = pkt["EAPOL"].len

    def csv(self):
        """
        Creates a list of the arguments required for an INSERT statement
        :return: list
        """
        return self.ether.csv() + [str(self.version), str(self.type), str(self.length)]
