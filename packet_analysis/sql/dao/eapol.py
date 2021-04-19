from scapy.all import Packet
from packet_analysis.sql.dao.sqlObject import sqlObject
from packet_analysis.sql.dao.ethernet import Ethernet


class EAPOL(sqlObject):
    """
     Object representing the information for the EAPOL information of a packet
    """

    def __init__(self, pkt: Packet):
        self.ether = Ethernet(pkt)
        self.version = pkt["EAPOL"].version
        self.type = pkt["EAPOL"].type
        self.length = pkt["EAPOL"].len

    @staticmethod
    def table_sql() -> str:
        """
        Constructs the necessary parameters for the table building as a string
        :return: str
        """
        return Ethernet.table_sql() + \
               """,
                  eapol_ver  STRING (40) NOT NULL,
                  type       STRING (40) NOT NULL,
                  eapol_len  INTEGER     NOT NULL"""

    def csv(self):
        """
        Creates a list of the arguments required for an INSERT statement
        :return: list
        """
        return self.ether.csv() + [str(self.version), str(self.type), str(self.length)]
