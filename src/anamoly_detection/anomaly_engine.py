from scapy.all import Packet

class AnomalyEngine:
    def __init__(self, frequency_signatures, traffic_signatures):
        # Lists of signatures that will be used in the engine
        self.frequency_signatures = frequency_signatures
        self.traffic_signatures = traffic_signatures

    def CheckSignatures(self, pkt: Packet):
        for f in self.frequency_signatures:
            f(pkt)
        for t in self.traffic_signatures:
            t(pkt)

