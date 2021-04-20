from scapy.packet import Packet

from src.database.models import DeviceInformation
from src.dashboard.alerts.alert import Alert, AlertType, Severity
from src.anamoly_detection.frequency_signatures.abstract_frequency_signature import AbstractFrequencySignature


class TrafficLayerFrequencySignature(AbstractFrequencySignature):
    """
    Signature class for representing traffic layer frequency limits
    """

    def __init__(self, equation, dev_equation, layer: str, window_size=3600, interval_size=600):
        """
        Initializes the signature using the super class, and it's unique information
        :param equation: function used to evaluate the average
        :param dev_equation: function used to evaluate the deviation
        :param layer: layer which is being limited
        :param window_size: Size of the window to limit (Limit is applied to this time frame, in seconds)
        :param interval_size: Segmented window size, sets how often windows are adjusted
        """
        super(TrafficLayerFrequencySignature, self).__init__(equation, dev_equation,
                                                             window_size=window_size, interval_size=interval_size)
        # Layer being checked (Will not increase unless seen)
        self._layer = layer

    def __call__(self, packet: Packet):
        """
        Function call to trigger the signature, alerts if matches and is over set limit
        :param packet: Packet being analyzed
        :return: None
        """
        if self._layer in packet:
            # Calculate the hour in which the packet was transmitted
            hour = (packet.time % 86400) / 3600

            # Adjust frequencies and limits based on time
            self.adjust_frequencies(hour)

            # If the frequency is above the adjusted average, create and Alert
            if self._current_average + self._current_deviation * 2 < self._window_frequency:
                dst = False
                if packet["Ethernet"].src not in DeviceInformation.get_mac_addresses():
                    dst = True
                Alert(packet,
                      "Traffic based anomaly detection shows above usual rates of {0} traffic. {1} packets"
                      " seen in last {2} seconds".format(self._layer, self._window_frequency, self._window_size),
                      AlertType.ANOMALY, Severity.WARN, dst).alert()
