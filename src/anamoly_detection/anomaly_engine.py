from scapy.all import Packet
from src.anamoly_detection.equation_parser import parse_equation
from src.database.models import AnomalyEquations
from src.anamoly_detection.frequency_signatures.traffic.traffic_layer_frequency_signature \
    import TrafficLayerFrequencySignature


class AnomalyEngine:
    """
    Engine object used to manage anomaly signatures
    """

    def __init__(self, connection, frequency_signatures=[], traffic_signatures=[]):
        """
        Creates an engine object using the given connection, defaulting to no signatures present
        :param connection: DB connection used to retrieve limit information
        :param frequency_signatures: Frequency based signatures (Time based limits)
        :param traffic_signatures: Traffic based signatures (Traffic type based limits)
        """
        # Save connection and create a session if necessary
        self.connection = connection
        if not self.connection.session:
            self.connection.create_session()

        # Lists of signatures that will be used in the engine
        self.frequency_signatures = frequency_signatures
        self.traffic_signatures = traffic_signatures

        # Get the equation data from the database
        if connection:
            limit_data = self.GetEquationStrings()

            # Format equations
            self.FormatEquation(limit_data)

    def GetEquationStrings(self) -> list:
        """
        Retrieves the frequency based limit equations from the DB
        :return: List of row information from DB
        """
        rows = self.connection.session.query(AnomalyEquations)
        self.connection.session.flush()
        parsed_rows = []
        for obj in rows:
            # Tuple of data from the sql DAO
            parsed_rows.append((obj.average_equation, obj.deviation_equation,
                                obj.layer, obj.window_size, obj.interval_size))
        return parsed_rows

    def FormatEquation(self, rows: list):
        """
        Formats the equation into a callable function within Python
        :param rows: List of lists of information regarding the equation/signature
        :return: None
        """
        for row in rows:
            # Split row into the data within the tuple
            avg_eq_cof, dev_eq_cof, layer, window_size, interval_size = row

            # Parse coefficients of the equations into callable functions
            avg_eq = parse_equation(avg_eq_cof)
            dev_eq = parse_equation(dev_eq_cof)

            # Add signature object created from DB information to the engine
            self.frequency_signatures.append(TrafficLayerFrequencySignature(avg_eq, dev_eq,
                                                                            layer, window_size, interval_size))

    def CheckSignatures(self, pkt: Packet):
        """
        Loop through the signatures to test the packet
        :param pkt: Packet retrieved from sniffing
        :return: None
        """
        for f in self.frequency_signatures:
            f(pkt)
        for t in self.traffic_signatures:
            t(pkt)
