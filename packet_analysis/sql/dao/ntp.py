from scapy.all import Packet
from packet_analysis.sql.dao.sqlObject import sqlObject
from packet_analysis.sql.dao.udp import UDP, table_sql as udp_table_sql


def table_sql() -> str:
    """
    Constructs the necessary parameters for the table building as a string
    :return: str
    """
    return udp_table_sql() + \
           """,
              ref_id    STRING (64) NOT NULL,
              id        STRING (64) NOT NULL,
              npt_ver   STRING (40) NOT NULL"""


class NTPHeader(sqlObject):
    """
    Object holding the information for an NTP header
    """

    def __init__(self, pkt: Packet):
        self.udp = UDP(pkt)
        self.ref_id = pkt["NTPHeader"].ref_id
        self.id = pkt["NTPHeader"].id
        self.version = pkt["NTPHeader"].version

    def csv(self):
        """
        Creates a list of the arguments required for an INSERT statement
        :return: list
        """
        return self.udp.csv() + [str(self.ref_id), str(self.id), str(self.version)]
