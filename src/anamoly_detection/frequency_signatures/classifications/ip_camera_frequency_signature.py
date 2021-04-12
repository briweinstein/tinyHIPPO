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

        # Frequency for the window as a whole, and for the segments that make up the sliding window
        self._window_frequency = 0
        self._interval_frequencies = deque(maxlen=(ceil(window_size / interval_size)))
        self._last_interval = 0
        self._current_average = 0
        self._current_deviation = 0

        # Fill with 0's
        for x in self._interval_frequencies:
            self._interval_frequencies.append(0)

        # Sizes used to evaluate when to shift the window
        self._window_size = window_size
        self._interval_size = interval_size

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

    def adjust_frequencies(self, hour, calculate_equation=False):
        if ((self._last_interval + self._window_size) % 24 < hour or
                (hour - self._window_size) % 24 > self._last_interval):
            self._last_interval = (self._last_interval + self._interval_size) % 24
            interval_freq = self._interval_frequencies[0]
            self._interval_frequencies.popleft()
            self._interval_frequencies.append(0)
            self._window_frequency -= interval_freq

            # Loop through until interval is caught up, in case of extremely rare traffic
            self.adjust_frequencies(hour, calculate_equation=True)
            return

        # Check again to make sure newly adjusted window is correct (In case multiple shifts are necessary)
        # Adjust the equation's current totals if necessary (Once per interval adjustment)
        if not ((self._last_interval + self._window_size) % 24 < hour or
                (hour - self._window_size) % 24 > self._last_interval):
            if calculate_equation:
                cumulative_average = 0
                cumulative_deviation = 0
                intervals = len(self._interval_frequencies)
                for x in range(intervals):
                    cumulative_average += self._limit_equation(self._last_interval +
                                                               ((((x + 1) * self._interval_size) / 3600) % 86400))
                    cumulative_deviation += self._deviation_equation((self._last_interval +
                                                                     (((x + 1) * self._interval_size) / 3600)) % 86400)
                self._current_average = cumulative_average
                self._current_deviation = cumulative_deviation

            # Increase frequency
            self._interval_frequencies[-1] += 1
            self._window_frequency += 1

    def __call__(self, packet: Packet):
        hour = (packet.time % 86400) / self._window_size
        self.adjust_frequencies(hour)

        if self._current_average + self._current_deviation > self._window_frequency:
            dst = False
            if packet["Ethernet"].src not in run_config.mac_addrs:
                dst = True
            Alert(packet, "Something happens", ALERT_TYPE.ANOMALY, SEVERITY.WARN, dst)
