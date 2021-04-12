from math import ceil
from collections import deque
from scapy.packet import Packet

from src import run_config
from src.dashboard.alerts.alert import Alert, AlertType, Severity
from src.anamoly_detection.frequency_signatures.abstract_frequency_signature import AbstractFrequencySignature


class TrafficLayerFrequencySignature(AbstractFrequencySignature):
    def __init__(self, equation, dev_equation, layer: str, window_size=3600, interval_size=600):
        # Lambda function equations
        self.limit_equation = equation
        self.deviation_equation = dev_equation

        # Layer being checked
        self.layer = layer

        # Frequency for the window as a whole, and for the segments that make up the sliding window
        self.window_frequency = 0
        self.interval_frequencies = deque(maxlen=(ceil(window_size / interval_size)))
        self.last_interval = 0
        self.current_average = 0
        self.current_deviation = 0

        # Fill with 0's
        for x in self._interval_frequencies:
            self.interval_frequencies.append(0)

        # Sizes used to evaluate when to shift the window
        self.window_size = window_size
        self.interval_size = interval_size

    def get_window_frequency(self):
        return self._window_frequency

    def _set_window_frequency(self, value: int):
        self._window_frequency = value

    def get_intervals(self):
        return self._interval_frequencies

    def _set_intervals(self, value: deque):
        self._interval_frequencies = value

    def get_limit_equation(self):
        return self._limit_equation

    def _set_limit_equation(self, value):
        self._limit_equation = value

    def get_last_interval(self):
        return self._last_interval

    def _set_last_interval(self, value):
        self._last_interval = value

    def get_deviation_equation(self):
        return self.deviation_equation

    def _set_deviation_equation(self, value):
        self.deviation_equation = value

    def get_window_size(self):
        return self.window_size

    def _set_window_size(self, value: int):
        self.window_size = value

    def get_interval_size(self):
        return self.interval_size

    def _set_interval_size(self, value: int):
        self.interval_size = value

    def __call__(self, packet: Packet):
        if self.layer in packet:
            hour = (packet.time % 86400) / self.window_size
            self.adjust_frequencies(hour)

            if self._current_average + self._current_deviation > self._window_frequency:
                dst = False
                if packet["Ethernet"].src not in run_config.mac_addrs:
                    dst = True
                Alert(packet,
                      "Traffic based anomaly detection shows above usual rates of {0} traffic.".format(self.layer),
                      AlertType.ANOMALY, Severity.WARN, dst)
