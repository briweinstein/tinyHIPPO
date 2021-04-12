import abc
from collections import deque
from scapy.all import Packet


class AbstractFrequencySignature(abc.ABC):
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
    def adjust_frequencies(self, hour):
        """

        :param hour:
        :return:
        """
        raise NotImplementedError

    @abc.abstractmethod
    def __call__(self, packet: Packet):
        """

        :param packet:
        :return:
        """
        raise NotImplementedError
