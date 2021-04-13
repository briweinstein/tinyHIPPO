import abc
from math import ceil, floor
from collections import deque
from scapy.all import Packet


class AbstractFrequencySignature(abc.ABC):
    def __init__(self, equation, dev_equation, window_size=3600, interval_size=600):
        # Lambda function equations
        self._limit_equation = equation
        self._deviation_equation = dev_equation

        # Frequency for the window as a whole, and for the segments that make up the sliding window
        self._window_frequency = 0
        self._interval_frequencies = deque(maxlen=(ceil(window_size / interval_size)))
        self._last_interval = 0
        self._current_average = -1
        self._current_deviation = -1

        # Sizes used to evaluate when to shift the window
        self._window_size = window_size
        self._interval_size = interval_size

    def adjust_frequencies(self, hour, calculate_equation=False):
        """
        Adjusts the frequency information based on the current hour
        Slides the window if necessary and re-calculates the expected frequencies
        :param hour: x value used in equations, hour of packet
        :param calculate_equation: Flag to determine if the equation should be re-calculated
        :return: None
        """
        within_window_condition = ((hour - self._last_interval) % 24) < self._window_size / 3600
        if not within_window_condition:
            self._last_interval = (self._last_interval + self._interval_size / 3600) % 24

            # Shift over queue
            if len(self._interval_frequencies) >= 1:
                interval_freq = self._interval_frequencies[0]
                self._interval_frequencies.popleft()
                self._interval_frequencies.append(0)
                self._window_frequency -= interval_freq
            else:
                self._interval_frequencies.append(0)

            # Loop through until interval is caught up, in case of extremely rare traffic
            self.adjust_frequencies(hour, calculate_equation=True)
            return

        # Check again to make sure newly adjusted window is correct (In case multiple shifts are necessary)
        # Adjust the equation's current totals if necessary (Once per window adjustment, default 10 minutes)
        if within_window_condition:
            if calculate_equation or (self._current_average == -1 and self._current_deviation == -1):
                cumulative_average = 0
                cumulative_deviation = 0
                intervals = ceil(self._window_size / self._interval_size)
                for x in range(intervals):
                    interval = round((self._last_interval + ((x * self._interval_size) / 3600)) % 24, 3)
                    print("AVG for {0} interval is: {1}".format(interval, self._limit_equation(interval)))
                    cumulative_average += self._limit_equation(interval)
                    cumulative_deviation += self._deviation_equation(interval)

                if intervals > 0:
                    self._current_average = cumulative_average / intervals
                    self._current_deviation = cumulative_deviation / intervals

            # Check to make sure the queue is caught up
            # (Only done during first window, makes sure to populate correctly)
            if len(self._interval_frequencies) < ceil(self._window_size / self._interval_size):
                while len(self._interval_frequencies) < \
                        ceil(((hour - self._last_interval % 24) * 3600) / self._interval_size) and \
                        len(self._interval_frequencies) < ceil(self._window_size / self._interval_size):
                    self._interval_frequencies.append(0)

            self._interval_frequencies[-1] += 1
            self._window_frequency += 1

    @abc.abstractmethod
    def __call__(self, packet: Packet):
        """
        Callable function that is evaluated to determine and trigger the Alert if necessary
        :param packet: Packet to analyze
        :return: None
        """
        raise NotImplementedError
