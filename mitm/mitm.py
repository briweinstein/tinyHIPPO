#! /usr/bin/env python3
from scapy.all import sniff, TCP, TLSClientHello, TLSExtEllipticCurves, TLSExtECPointsFormat, IP, IPv6, TCP, UDP
import urllib.request
from cids_main import run_config

# TODO: Retries

# TODO: how sequential should this be???
# Possible statuses, based on last seen packet:
#  - "Uninitialized":       The MitM process has not yet begun
#  - "ClientHello":         IoT -> Target
#  - "ServerHello":         IoT <- Target
#  - "Certificate":         IoT <- Target
#  - "ServerKeyExchange":   IoT <- Target (CertificateStatus, ServerKeyExchange, ServerHelloDone)
#  - "ClientKeyExchange":   IoT -> Target (ClientKeyExchange, ChangeCipherSpec, Finished)
#  - "NewSessionTicket":    IoT <- Target (NewSessionTicket, ChangeCipherSpec, Finished)
#  - "ApplicationData":     IoT -> Target
#  - "Completed":           The MitM process is completed
class MitM:
    def __init__(self):
        self.status = "Uninitialized"
        self.success = False
        self.mac_addrs = []
        for addr in run_config.mac_addrs:
            self.mac_addrs.append(addr.lower())

        self.router_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
        print("router ip: " + self.router_ip)

    # Determine what kind of packet to process, if any
    def __call__(self, packet):
        print("MitM called")

        if not packet.haslayer(TCP):
            return

        self.__print_stuff()

        packet_types = ["TLSClientHello", "TLSServerHello", "TLSCertificate",
                        "TLSCertificateStatus", "TLSServerKeyExchange", "TLSServerHelloDone",
                        "TLSClientKeyExchange", "", "TLSFinished"
                        "TLSNewSessionTicket", "", "TLSFinished"
                        "", ""]

        unused_packet_types = ["TLSHelloRequest", "TLSHelloVerifyRequest", "TLSNewSessionTicket",
                               "TLSEncryptedExtensions", "TLSCertificateRequest", "TLSServerHelloDone",
                               "TLSCertificateVerify", "TLSCertificateURL", "TLSCertificateStatus",
                               "TLSSupplementalData"]

        for type in packet_types:
            if packet[TCP].haslayer(type):
                self.__process_packet(packet, self.__process_ClientHello)
                return

    ##############################################################################################

    def __process_packet(self, packet, packet_func):
        if self.__is_packet_expected:
            packet_func(packet)
        else:
            self.status = "Uninitialized"

    def __is_packet_expected(self, packet):
        if self.status

    ##############################################################################################

    def __process_ClientHello(self, packet):
        ip_type, proto_type = None
        if packet.haslayer(IP):
            ip_type = IP
        elif packet.haslayer(IPv6):
            ip_type = IPv6
        else:
            return
        sip = packet[ip_type].src
        dip = packet[ip_type].dst

        if packet.haslayer(TCP):
            proto_type = TCP
        elif packet.haslayer(UDP):
            proto_type = UDP
        else:
            return
        sp = packet[proto_type].sport
        dp = packet[proto_type].dport

        # Just switch out the sip, dip, sp, and dp?

    ##############################################################################################

    def __print_stuff(self):
        print("ciphersuite: " + self.packet[TLSClientHello].cipher_suites)
        print("compression_length: " + self.packet[TLSClientHello].compression_methods_length)
        print("compression: " + self.packet[TLSClientHello].compression_methods)
        print("extensions: " + self.packet[TLSClientHello].extensions)
        if self.packet.haslayer(TLSExtEllipticCurves):
            print("e_curves: " + self.packet[TLSExtEllipticCurves].elliptic_curves)
        if self.packet.haslayer(TLSExtECPointsFormat):
            print("ec_points_fmt: " + self.packet[TLSExtECPointsFormat].ec_point_formats)

    ##############################################################################################

# Sources
# https://gist.github.com/allansto/8e47c2998995d0d8b781c88936b4624a

