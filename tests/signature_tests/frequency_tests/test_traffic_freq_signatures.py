import unittest
import unittest.mock as um
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from src.anamoly_detection.frequency_signatures.traffic.traffic_layer_frequency_signature \
    import TrafficLayerFrequencySignature
from src.anamoly_detection.equation_parser import parse_equation

root_path_test_data = "../../test_data/"


class TestIPSignature(unittest.TestCase):
    def setUp(self) -> None:
        eq = parse_equation("1,2,3")    # f(x) = x + 2(x ^ 2) + 3
        dev_eq = parse_equation("0")    # f(x) = 0
        layer = "UDP"
        self.signature = TrafficLayerFrequencySignature(eq, dev_eq, layer)
        self.trigger_packet = Ether() / IP() / UDP(dport=80)
        self.no_trigger_packet = Ether() / IP() / TCP(dport=80)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_queue_wrapping(self, mock_alert):
        """
        Test the no alert is triggered when within acceptable levels, and that the queue properly flushes and fills
        :param mock_alert: Mocked alert class
        :return: None
        """
        self.trigger_packet.time = 1618185601.00  # Hour 0, Minute 0, Second 1
        self.signature(self.trigger_packet)

        # Frequency properly triggers
        self.assertEqual(1, self.signature._window_frequency)
        # Deviation and average calculate correctly for hour 0
        self.assertEqual(0, self.signature._current_deviation)        # Static 0 constant
        self.assertGreater(0.1, 4 - self.signature._current_average)  # Estimated integral value of equation
        # Interval queue is as expected (Last item is 1, rest are 0) (Length 6)
        intervals = list(self.signature._interval_frequencies)
        self.assertEqual(1, intervals[-1])          # Expect 1 interval in the queue with 1 value
        self.assertEqual(0, intervals.count(0))     # Expect no 0's, since this is the first item in the queue

        self.trigger_packet.time += 1800  # Hour 0, Minute 30, Second 1
        self.signature(self.trigger_packet)
        self.assertEqual(2, self.signature._window_frequency)
        intervals = list(self.signature._interval_frequencies)
        self.assertEqual(1, intervals[-1])
        self.assertEqual(2, intervals.count(1))
        self.assertEqual(2, intervals.count(0))  # Queue: 1, 0, 0, 1

        self.trigger_packet.time += 1800  # Hour 1, Minute 0, Second 1
        self.signature(self.trigger_packet)
        self.assertEqual(2, self.signature._window_frequency)
        intervals = list(self.signature._interval_frequencies)
        self.assertEqual(1, intervals[-1])
        self.assertEqual(2, intervals.count(1))
        self.assertEqual(4, intervals.count(0))  # Queue: 0, 0, 1, 0, 0, 1

        self.trigger_packet.time += 79200  # Hour 23, Minute 0, Second 1
        self.signature(self.trigger_packet)
        self.assertEqual(1, self.signature._window_frequency)
        intervals = list(self.signature._interval_frequencies)
        self.assertEqual(1, intervals[-1])
        self.assertEqual(1, intervals.count(1))
        self.assertEqual(5, intervals.count(0))  # Queue: 0, 0, 0, 0, 0, 1

        self.trigger_packet.time += 5400  # Hour 0, Minute 30, Second 1
        self.signature(self.trigger_packet)
        self.assertEqual(1, self.signature._window_frequency)
        intervals = list(self.signature._interval_frequencies)
        self.assertEqual(1, intervals[-1])
        self.assertEqual(1, intervals.count(1))
        self.assertEqual(5, intervals.count(0))  # Queue: 0, 0, 0, 0, 0, 1

        self.trigger_packet.time += 1800  # Hour 1, Minute 0, Second 1
        self.signature(self.trigger_packet)
        self.assertEqual(2, self.signature._window_frequency)
        intervals = list(self.signature._interval_frequencies)
        self.assertEqual(1, intervals[-1])
        self.assertEqual(2, intervals.count(1))
        self.assertEqual(4, intervals.count(0))  # Queue: 0, 0, 1, 0, 0, 1

        # No alert should be triggered
        self.assertEqual(0, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_above_acceptable_levels(self, mock_alert):
        """
        Test the no alert is triggered when within acceptable levels, and that the queue properly flushes and fills
        :param mock_alert: Mocked alert class
        :return: None
        """
        self.trigger_packet.time = 1618185601.00  # Hour 0, Minute 0, Second 1
        self.signature(self.trigger_packet)
        self.signature(self.trigger_packet)
        self.signature(self.trigger_packet)
        self.signature(self.trigger_packet)

        # Frequency properly triggers
        self.assertEqual(4, self.signature._window_frequency)
        # Deviation and average calculate correctly for hour 0
        self.assertEqual(0, self.signature._current_deviation)  # Static 0 constant
        self.assertGreater(0.1, 4 - self.signature._current_average)  # Estimated integral value of equation
        # Interval queue is as expected (Last item is 1, rest are 0) (Length 6)
        intervals = list(self.signature._interval_frequencies)
        self.assertEqual(4, intervals[-1])  # Expect 1 interval in the queue with 1 value
        self.assertEqual(0, intervals.count(0))  # Expect no 0's, since this is the first item in the queue

        self.trigger_packet.time += 3600  # Hour 1, Minute 0, Second 1
        self.signature(self.trigger_packet)
        self.assertEqual(1, self.signature._window_frequency)

        # No alert should be triggered
        self.assertEqual(1, mock_alert.call_count)

    @um.patch("src.dashboard.alerts.alert.Alert.alert")
    def test_different_traffic(self, mock_alert):
        """
        Test the no alert is triggered when within acceptable levels, and that the queue properly flushes and fills
        :param mock_alert: Mocked alert class
        :return: None
        """
        self.no_trigger_packet.time = 1618185601.00  # Hour 0, Minute 0, Second 1
        self.signature(self.no_trigger_packet)
        self.signature(self.no_trigger_packet)
        self.signature(self.no_trigger_packet)
        self.signature(self.no_trigger_packet)

        # Frequency properly triggers
        self.assertEqual(0, self.signature._window_frequency)
        intervals = list(self.signature._interval_frequencies)
        self.assertEqual(0, len(intervals))  # Expect nothing since no packets have been seen

        # No alert should be triggered
        self.assertEqual(0, mock_alert.call_count)

    def tearDown(self) -> None:
        pass


if __name__ == '__main__':
    unittest.main()
