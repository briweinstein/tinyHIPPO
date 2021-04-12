import abc
from collections import deque
from scapy.all import Packet


class AbstractFrequencySignature(abc.ABC):
    """
    Abstract class representing the most basic frequency signatures, logic, and the requirements for such
    """
    @abc.abstractmethod
    def get_window_frequency(self):
        ...

    @abc.abstractmethod
    def _set_window_frequency(self, value: int):
        ...

    # The total frequency of signature matches for a given window
    window_frequency = property(get_window_frequency, _set_window_frequency)

    @abc.abstractmethod
    def get_last_interval(self):
        ...

    @abc.abstractmethod
    def _set_last_interval(self, value):
        ...

    # The total frequency of signature matches for a given window
    last_interval = property(get_last_interval, _set_last_interval)

    @abc.abstractmethod
    def get_intervals(self):
        ...

    @abc.abstractmethod
    def _set_intervals(self, value: deque):
        ...

    # The queue of the frequency of signature matches for a given window, each value represent an interval
    interval_frequencies = property(get_intervals, _set_intervals)

    @abc.abstractmethod
    def get_limit_equation(self):
        ...

    @abc.abstractmethod
    def _set_limit_equation(self, value):
        ...

    # All frequency signatures contain a function that produces the upper limit from analysis
    # This function is based off of the current time, based in hours
    limit_equation = property(get_limit_equation, _set_limit_equation)

    @abc.abstractmethod
    def get_deviation_equation(self):
        ...

    @abc.abstractmethod
    def _set_deviation_equation(self, value):
        ...

    # All frequency signatures contain a function that produces the variation allowable for each limit
    # This function is based off of the current time, based in hours
    deviation_equation = property(get_deviation_equation, _set_deviation_equation)

    @abc.abstractmethod
    def get_window_size(self):
        ...

    @abc.abstractmethod
    def _set_window_size(self, value: int):
        ...

    # The size of the window used for evaluation in seconds
    window_size = property(get_window_size, _set_window_size)

    @abc.abstractmethod
    def get_interval_size(self):
        ...

    @abc.abstractmethod
    def _set_interval_size(self, value: int):
        ...

    # The size of each interval used for evaluation in seconds
    interval_size = property(get_interval_size, _set_interval_size)

    @abc.abstractmethod
    def get_current_average(self):
        ...

    @abc.abstractmethod
    def _set_current_average(self, value: int):
        ...

    # The size of each interval used for evaluation in seconds
    current_average = property(get_current_average, _set_current_average)

    @abc.abstractmethod
    def get_current_deviation(self):
        ...

    @abc.abstractmethod
    def _set_current_deviation(self, value: int):
        ...

    # The size of each interval used for evaluation in seconds
    current_deviation = property(get_current_deviation, _set_current_deviation)

    def adjust_frequencies(self, hour, calculate_equation=False):
        """
        Adjusts the frequency information based on the current hour
        Slides the window if necessary and re-calculates the expected frequencies
        :param hour: x value used in equations, hour of packet
        :param calculate_equation: Flag to determine if the equation should be re-calculated
        :return: None
        """
        if ((self.last_interval + self.window_size) % 24 < hour or
                (hour - self.window_size) % 24 > self.last_interval):
            self.last_interval = (self.last_interval + self.interval_size) % 24
            interval_freq = self.interval_frequencies[0]
            self.interval_frequencies.popleft()
            self.interval_frequencies.append(0)
            self.window_frequency -= interval_freq

            # Loop through until interval is caught up, in case of extremely rare traffic
            self.adjust_frequencies(hour, calculate_equation=True)
            return

        # Check again to make sure newly adjusted window is correct (In case multiple shifts are necessary)
        # Adjust the equation's current totals if necessary (Once per interval adjustment)
        if not ((self.last_interval + self.window_size) % 24 < hour or
                (hour - self.window_size) % 24 > self.last_interval):
            if calculate_equation:
                cumulative_average = 0
                cumulative_deviation = 0
                intervals = len(self.interval_frequencies)
                for x in range(intervals):
                    cumulative_average += self.limit_equation(self.last_interval +
                                                              ((((x + 1) * self.interval_size) / 3600) % 86400))
                    cumulative_deviation += self.deviation_equation((self.last_interval +
                                                                     (((x + 1) * self.interval_size) / 3600)) % 86400)
                self.current_average = cumulative_average
                self.current_deviation = cumulative_deviation

            # Increase frequency
            self.interval_frequencies[-1] += 1
            self.window_frequency += 1

    @abc.abstractmethod
    def __call__(self, packet: Packet):
        """
        Callable function that is evaluated to determine and trigger the Alert if necessary
        :param packet: Packet to analyze
        :return: None
        """
        raise NotImplementedError
