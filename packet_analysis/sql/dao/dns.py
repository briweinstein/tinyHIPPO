from scapy.all import Packet
from packet_analysis.sql.dao.sqlObject import sqlObject
from packet_analysis.sql.dao.udp import UDP, table_sql as udp_table_sql
from packet_analysis.sql.dao.tcp import TCP, table_sql as udp_table_sql


def table_sql() -> str:
    """
    Constructs the necessary parameters for the table building as a string
    :return: str
    """
    return udp_table_sql() + \
           """,
              is_tcp   BOOLEAN     NOT NULL,
              qname    STRING (40) NOT NULL,
              qtype    STRING (40) NOT NULL,
              qclass   STRING (40) NOT NULL"""


class DNS(sqlObject):
    """
     Object representing the information for the DNS information of a packet
    """

    def __init__(self, pkt: Packet):
        if "TCP" in pkt:
            self.udp_tcp = TCP(pkt)
            self.is_tcp = True
        else:
            self.udp_tcp = UDP(pkt)
            self.is_tcp = False

        # Get question record
        question_record = pkt["DNS"].qd
        if question_record:
            self.qname = question_record.qname
            self.qtype = question_record.qtype
            self.qclass = question_record.qclass
        else:
            self.qname = ""
            self.qtype = ""
            self.qclass = ""

    def csv(self):
        """
        Creates a list of the arguments required for an INSERT statement
        :return: list
        """
        return self.udp_tcp.csv() + [str(self.is_tcp), str(self.qname), str(self.qtype), str(self.qclass)]
