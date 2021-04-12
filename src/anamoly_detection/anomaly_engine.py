from scapy.all import Packet
from sqlite3 import Connection

class AnomalyEngine:
    @staticmethod
    def GetEquationStrings(connection: Connection):
        # Format the fill query
        # TODO: Setup SQL retrieval, add list of conditions to equations

        sql_str = "SELECT {0} FROM {1} WHERE {2};".format(",".join(columns), table, " AND ".join(conditions))

        # Execute and retrieve rows
        cursor = connection.cursor()
        cursor.execute(sql_str)
        rows = cursor.fetchall()
        cursor.close()

    def __init__(self, connection: Connection, frequency_signatures=[], traffic_signatures=[]):
        # Lists of signatures that will be used in the engine
        self.frequency_signatures = frequency_signatures
        self.traffic_signatures = traffic_signatures


    def CheckSignatures(self, pkt: Packet):
        for f in self.frequency_signatures:
            f(pkt)
        for t in self.traffic_signatures:
            t(pkt)

