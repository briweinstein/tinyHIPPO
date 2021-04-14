from scapy.all import Packet
from src.anamoly_detection.equation_parser import parse_equation
from src.database.models import AnomalyEquations
from src.database.db_connection import DBConnection
from src.anamoly_detection.frequency_signatures.traffic.traffic_layer_frequency_signature \
    import TrafficLayerFrequencySignature


class AnomalyEngine:
    def GetEquationStrings(self):
        rows = self.connection.session.query(AnomalyEquations)
        self.connection.session.flush()
        parsed_rows = []
        for obj in rows:
            # Tuple of data from the sql DAO
            parsed_rows.append((obj.average_equation, obj.deviation_equation,
                               obj.layer, obj.window_size, obj.interval_size))
        return parsed_rows

    def __init__(self, connection, frequency_signatures=[], traffic_signatures=[]):
        self.connection = connection
        self.connection.create_session()

        # Lists of signatures that will be used in the engine
        self.frequency_signatures = frequency_signatures
        self.traffic_signatures = traffic_signatures

        # Get the equation data from the database
        if connection:
            limit_data = self.GetEquationStrings()

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
