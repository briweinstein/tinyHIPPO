from scapy.all import Packet
from packet_analysis.sql.dao.sqlObject import sqlObject
from packet_analysis.sql.dao.ethernet import Ethernet


class ARP(sqlObject):
    """
    Object holding the information for an ARP packet
    """

    def __init__(self, pkt: Packet):
        self.ether = Ethernet(pkt)

    @staticmethod
    def table_sql() -> str:
        """
        Constructs the necessary parameters for the table building as a string
        :return: str
        """
        return Ethernet.table_sql()

    def csv(self):
        """
        Creates a list of the arguments required for an INSERT statement
        :return: list
        """
        return self.ether.csv()
