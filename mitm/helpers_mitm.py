#! /usr/bin/env python3
from scapy.all import TCP
from mitm.mitm_client_hello import MitMClientHello
from mitm.mitm_server_hello import MitMServerHello
from mitm.mitm_certificate import MitMCertificate
from mitm.mitm_certificate_status import MitMCertificateStatus
from mitm.mitm_server_key_exchange import MitMServerKeyExchange
from mitm.mitm_server_hello_done import MitMServerHelloDone
from mitm.mitm_client_key_exchange import MitMClientKeyExchange
from mitm.mitm_finished import MitMFinished
from mitm.mitm_new_session_ticket import MitMNewSessionTicket

packet_types_functions = {"TLSClientHello": MitMClientHello(), "TLSServerHello": MitMServerHello(),
                          "TLSCertificate": MitMCertificate(), "TLSCertificateStatus": MitMCertificateStatus(),
                          "TLSServerKeyExchange": MitMServerKeyExchange(), "TLSServerHelloDone": MitMServerHelloDone(),
                          "TLSClientKeyExchange": MitMClientKeyExchange(), "TLSFinished": MitMFinished(),
                          "TLSNewSessionTicket": MitMNewSessionTicket()}

alternate_packet_types = ["TLSHelloRequest", "TLSHelloVerifyRequest", "TLSNewSessionTicket", "TLSEncryptedExtensions",
                          "TLSCertificateRequest", "TLSServerHelloDone", "TLSCertificateVerify", "TLSCertificateURL",
                          "TLSCertificateStatus", "TLSSupplementalData"]


def get_session_packet_type(packet):
    """
    Gets the session packet type or returns False if the packet does not have a type that is in the MitM process
    Possible MitM process session packet types in "packet_types"
    """
    for type in list(packet_types_functions.keys()):
        if packet[TCP].haslayer(type):
            return type
    return False


def get_packet_type_functions():
    """
    Gets the "packet_types" list
    """
    return packet_types_functions

