from math import ceil
from collections import deque
from scapy.packet import Packet

from src import run_config
from src.database.models import DeviceInformation
from src.dashboard.alerts.alert import Alert, AlertType, Severity
from src.anamoly_detection.frequency_signatures.abstract_frequency_signature import AbstractFrequencySignature


class TrafficLayerFrequencySignature(AbstractFrequencySignature):
    def __init__(self, equation, dev_equation, layer: str, window_size=3600, interval_size=600):
        super(TrafficLayerFrequencySignature, self).__init__(equation, dev_equation,
                                                             window_size=window_size, interval_size=interval_size)
        # Layer being checked (Will not increase unless seen)
        self._layer = layer

    def __call__(self, packet: Packet):
        if self._layer in packet:
            hour = (packet.time % 86400) / self._window_size
            print("Adjusting...")
            self.adjust_frequencies(hour)

            print("FREQ: " + str(self._interval_frequencies))
            print("DEV : " + str(self._current_deviation))
            print("AVG : " + str(self._current_average))
            if self._current_average + self._current_deviation > self._window_frequency:
                dst = False
                if packet["Ethernet"].src not in DeviceInformation.get_mac_addresses():
                    dst = True
                Alert(packet,
                      "Traffic based anomaly detection shows above usual rates of {0} traffic. {1} packets"
                      " seen in last {2} seconds".format(self._layer, self._window_frequency, self._window_size),
                      AlertType.ANOMALY, Severity.WARN, dst)
