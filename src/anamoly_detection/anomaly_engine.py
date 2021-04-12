from scapy.all import Packet
from sqlite3 import Connection
from src.anamoly_detection.equation_parser import parse_equation
from src.anamoly_detection.frequency_signatures.traffic.traffic_layer_frequency_signature \
    import TrafficLayerFrequencySignature


class AnomalyEngine:
    @staticmethod
    def GetEquationStrings(connection: Connection):
        # Format the fill query
        table = "anomaly_equations"
        columns = ["average_equation", "adjustment_equation", "layer", "window_size", "interval_size"]

        sql_str = "SELECT {0} FROM {1};".format(",".join(columns), table)

        # Execute and retrieve rows
        cursor = connection.cursor()
        cursor.execute(sql_str)
        rows = cursor.fetchall()
        cursor.close()

        return rows

    def __init__(self, connection: Connection, frequency_signatures=[], traffic_signatures=[]):
        # Lists of signatures that will be used in the engine
        self.frequency_signatures = frequency_signatures
        self.traffic_signatures = traffic_signatures

        # Get the equation data from the database
        if connection:
            limit_data = self.GetEquationStrings(connection)

            # Format equations
            self.FormatEquation(limit_data)

    def FormatEquation(self, rows: list):
        for row in rows:
            # Split row into the data within the tuple
            avg_eq_cof, dev_eq_cof, layer, window_size, interval_size = row

            # Parse coefficients of the equations into callable functions
            avg_eq = parse_equation(avg_eq_cof)
            dev_eq = parse_equation(dev_eq_cof)

            self.frequency_signatures.append(TrafficLayerFrequencySignature(avg_eq, dev_eq,
                                                                            layer, window_size, interval_size))

    def CheckSignatures(self, pkt: Packet):
        for f in self.frequency_signatures:
            f(pkt)
        for t in self.traffic_signatures:
            t(pkt)
