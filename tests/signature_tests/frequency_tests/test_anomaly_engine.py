import unittest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP

from src import db
from src.anamoly_detection.anomaly_engine import AnomalyEngine

# Setup engine once for testing
conn = db
engine = AnomalyEngine(db)

class TestIPSignature(unittest.TestCase):
    def test_engine(self):
        """
        Test that the engine initializes and properly populates its signatures
        :return: None
        """
        self.assertIsNotNone(engine)
        self.assertTrue(engine.frequency_signatures != [])
        self.assertTrue(engine.traffic_signatures == [])

        # Check that the returned rows are all turned into equations
        self.assertEqual(len(engine.GetEquationStrings()), len(engine.frequency_signatures))

    def test_engine_packet_handling(self):
        """
        Test that the signatures load properly and are called upon correctly by the engine
        :return: None
        """
        udp_packet = Ether() / IP() / UDP(dport=80)
        tcp_packet = Ether() / IP() / TCP(dport=80)

        # Call the engine using the two packets as parameters
        engine.CheckSignatures(udp_packet)
        engine.CheckSignatures(tcp_packet)

        # Confirm the signatures regarding IP & TCP/UDP are triggered (3 signatures in total)
        triggered_signatures = list(filter(lambda x: x._window_frequency > 0, engine.frequency_signatures))
        self.assertEqual(3, len(triggered_signatures))


if __name__ == '__main__':
    unittest.main()
