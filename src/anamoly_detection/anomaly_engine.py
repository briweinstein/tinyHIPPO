from scapy.all import Packet
from src.database.models import AnomalyEquations
from src.anamoly_detection.frequency_signatures.traffic.traffic_layer_frequency_signature \
    import TrafficLayerFrequencySignature


def parse_equation(coefficients: str):
    """
    Create a callable function representing an equation
    Function in form of:

        "a, b, ... , z" -> f(x) = (a * x) ... (y * x ^ ?) + z
                                 ...
        "a, b"          -> f(x) = (a * x) + b
        "a"             -> f(x) = a

    :param coefficients: CSV in string form of the coefficients
    :return: A callable function that calculates a polynomial of variable degree, based on given coefficients
    """
    # Equations exists as coefficients to a (len(coefficients) - 1) degree polynomial
    list_of_coefficients = coefficients.replace(" ", "").split(",")
    list_of_expressions = []
    degree = len(list_of_coefficients)
    current_degree = 1

    # Escape on no coefficients
    if degree == 0 or list_of_coefficients[0] == '':
        return lambda x: 0

    # Loop through coefficients, assigning them to their respective expressions based on degree
    for coefficient in list_of_coefficients:
        if coefficient == "0":
            # No need to waste time with 0 value coefficient
            continue
        if current_degree == degree:
            # Final value is always a constant (C)
            list_of_expressions.append(lambda x, cof=coefficient: float(cof))
        else:
            # [0:-2] coefficients are normal polynomials to the power of the current_degree
            list_of_expressions.append(lambda x, cof=coefficient, deg=current_degree: float(cof) * pow(x, deg))
        current_degree += 1

    # Return a function that sums up the value of each expression
    return lambda x: sum(list(map(lambda y: y(x), list_of_expressions)))


class AnomalyEngine:
    """
    Engine object used to manage anomaly signatures
    """

    def __init__(self, connection, frequency_signatures=None, traffic_signatures=None):
        """
        Creates an engine object using the given connection, defaulting to no signatures present
        :param connection: DB connection used to retrieve limit information
        :param frequency_signatures: Frequency based signatures (Time based limits)
        :param traffic_signatures: Traffic based signatures (Traffic type based limits)
        """
        if traffic_signatures is None:
            traffic_signatures = []
        if frequency_signatures is None:
            frequency_signatures = []

        # Save connection and create a session if necessary
        self.connection = connection
        if not self.connection.session:
            self.connection.create_session()

        # Lists of signatures that will be used in the engine
        self.frequency_signatures = frequency_signatures
        self.traffic_signatures = traffic_signatures

        # Get the equation data from the database
        if connection:
            limit_data = self.get_equation_strings()

            # Format equations
            self.format_equation(limit_data)

    def get_equation_strings(self) -> list:
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

    def format_equation(self, rows: list):
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

    def check_signatures(self, pkt: Packet):
        """
        Loop through the signatures to test the packet
        :param pkt: Packet retrieved from sniffing
        :return: None
        """
        for f in self.frequency_signatures:
            f(pkt)
        for t in self.traffic_signatures:
            t(pkt)
