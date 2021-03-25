from scapy.packet import Packet

from src import run_config
from src.dashboard.alerts.alert import Alert, ALERT_TYPE, SEVERITY
from src.anamoly_detection.traffic_signatures.abstract_traffic_signature import AbstractTrafficSignature, pull_layer

class BannedTraffic(AbstractTrafficSignature):
    def __init__(self, mac_addr="", traffic=None):
        if traffic is None:
            traffic = {}
        self._mac_addr = mac_addr
        self._traffic = traffic

    def __call__(self, packet: Packet):
        if "Ethernet" not in packet:
            raise Exception("Given packet does not have the necessary layers")
        layers = packet.layers()
        for layer in layers:
            if layer in self._traffic:
                dst = False
                if packet["Ethernet"].src not in run_config.mac_addrs:
                    dst = True
                desc = "Banned traffic found ({0})".format(pull_layer(layer))
                Alert(packet, desc, ALERT_TYPE.ANOMALY, SEVERITY.WARN, dst).alert()

    def add_traffic_types(self, new_traffic: set):
        self._traffic |= new_traffic

    def remove_traffic_types(self, remove_traffic: set):
        self._traffic.difference_update(remove_traffic)
