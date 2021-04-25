import abc
from math import ceil
from collections import deque
from scapy.all import Packet


class AbstractFrequencySignature(abc.ABC):
    """
    Abstract class representing any frequency based signature
    """

    def __init__(self, equation, dev_equation, window_size=3600, interval_size=600):
        """
        Super constructor for implementing classes
        Initializes the signature using the super class, and it's unique information
        :param equation: function used to evaluate the average
        :param dev_equation: function used to evaluate the deviation
        :param window_size: Size of the window to limit (Limit is applied to this time frame, in seconds)
        :param interval_size: Segmented window size, sets how often windows are adjusted
        """
        # Lambda function equations
        self._limit_equation = equation
        self._deviation_equation = dev_equation

        # Frequency for the window as a whole, and for the segments that make up the sliding window
        self._window_frequency = 0
        self._interval_frequencies = deque(maxlen=(ceil(window_size / interval_size)))
        self._last_interval = 0

        # Average and deviation calculated for the current window
        self._current_average = -1
        self._current_deviation = -1

        # Sizes used to evaluate when to shift the window
        self._window_size = window_size
        self._interval_size = interval_size
        self._alerted_for_window = False

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

            # Reset window alert
            self._alerted_for_window = False

            # Loop through until interval is caught up, in case of extremely rare traffic
            self.adjust_frequencies(hour, calculate_equation=True)
            return

        # Check again to make sure newly adjusted window is correct (In case multiple shifts are necessary)
        # Adjust the equation's current totals if necessary (Once per window adjustment, default 10 minutes)
        if within_window_condition:
            # If no average has been set, or the window has been adjusted
            if calculate_equation or (self._current_average == -1 and self._current_deviation == -1):
                # Reset average and deviation
                cumulative_average = 0
                cumulative_deviation = 0
                intervals = ceil(self._window_size / self._interval_size)

                # Loop through intervals and re-calculate the averages using the set equations
                for x in range(intervals):
                    interval = round((self._last_interval + ((x * self._interval_size) / 3600)) % 24, 3)
                    cumulative_average += self._limit_equation(interval)
                    cumulative_deviation += self._deviation_equation(interval)

                # If there are intervals (i.e. any data triggered within time frame), calculate average over this time
                if intervals > 0:
                    divisor = max(1, 1800 // self._interval_size)
                    self._current_average = cumulative_average / divisor
                    self._current_deviation = cumulative_deviation / divisor

            # Check to make sure the queue is caught up
            # (Only done during first window, makes sure to populate correctly)
            if len(self._interval_frequencies) < ceil(self._window_size / self._interval_size):
                while len(self._interval_frequencies) < \
                        ceil(((hour - self._last_interval % 24) * 3600) / self._interval_size) and \
                        len(self._interval_frequencies) < ceil(self._window_size / self._interval_size):
                    self._interval_frequencies.append(0)

            # Adjust interval and window frequency
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
