#! /usr/bin/env python3
from mitm.mitm import MitM


class IoTDevice:
    def __init__(self, mac_addr):
        self.mac_addr = mac_addr
        self.mitm_sessions = []

    def get_mitm_session(self, packet):
        """
        Return the session for the given packet: either an existing or a new one
        """
        # Return an existing session if one exists
        for session in self.mitm_sessions:
            if (packet.src == session.client_ip_real) and (packet.dst == session.server_ip_real):
                return session

        # Return a new session as no existing session exists
        return MitM()
