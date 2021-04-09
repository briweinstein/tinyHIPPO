from math import ceil
from collections import deque
from scapy.packet import Packet

from src import run_config
from src.dashboard.alerts.alert import Alert, ALERT_TYPE, SEVERITY
from src.anamoly_detection.frequency_signatures.abstract_frequency_signature import AbstractFrequencySignature

class IPCameraFrequencySignature(AbstractFrequencySignature):
    def __init__(self, equation, dev_equation, window_size=3600, interval_size=600):
        # Lambda function equations
        self._limit_equation = equation
        self._deviation_equation = dev_equation

        # Sizes used to evaluate when to shift the window
        self._window_size = window_size
        self._interval_size = interval_size

    def get_window_size(self):
        return self._window_size

    def get_interval_size(self):
        return self._interval_size

    def get_limit_equation(self):
        return self._limit_equation

    def get_deviation_equation(self):
        return self._deviation_equation

    def __call__(self, packet: Packet):
        self._window_frequency += 1
        hour = (packet.time % 86400) / self._window_size
        expected_average = self._limit_equation(hour, self._interval_size)
        deviation = self._deviation_equation(hour, self._interval_size)

        if expected_average > self._window_frequency + deviation:
            dst = False
            if packet["Ethernet"].src not in run_config.mac_addrs:
                dst = True
            Alert(packet, "Something happens", ALERT_TYPE.ANOMALY, SEVERITY.WARN, dst)