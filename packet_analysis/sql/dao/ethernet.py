from scapy.all import Packet
from packet_analysis.sql.dao.sqlObject import sqlObject


def table_sql() -> str:
    """
    Constructs the necessary parameters for the table building as a string
    :return: str
    """
    return """id       INTEGER     PRIMARY KEY AUTOINCREMENT
                                   UNIQUE
                                   NOT NULL,
              time     DECIMAL     NOT NULL,
              hour     INTEGER     NOT NULL,
              day      INTEGER     NOT NULL,
              pkt_len  INTEGER     NOT NULL,
              src_mac  STRING (40) NOT NULL,
              dst_mac  STRING (40) NOT NULL"""


class Ethernet(sqlObject):
    """
    Object holding the information for an Ethernet frame as well as basic packet information
    """

    def __init__(self, pkt: Packet):
        self.time = pkt.time
        self.hour = round((self.time % 86400) / 3600, 2)
        self.day = (self.time % 31536000) // 86400
        self.length = len(pkt)
        self.src_mac = pkt["Ethernet"].src
        self.dst_mac = pkt["Ethernet"].dst

    def csv(self):
        """
        Creates a list of the arguments required for an INSERT statement
        :return: list
        """
        # Always include the 'None' for the first item in order to allow the auto-increment ID to work
        return [None, str(self.time), str(self.hour), str(self.day), self.length, str(self.src_mac), str(self.dst_mac)]
