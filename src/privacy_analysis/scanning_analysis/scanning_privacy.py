#! /usr/bin/env python3
import abc


# TODO: check TLS, scan with nmap
class ScanningPrivacy(abc.ABC):
    """
    This abstract base class represents a single privacy rule to be checked against IoT devices in our IoT Privacy Protection System
    """

    @property
    def msg(self):
        return type(self).__name__

    @abc.abstractmethod
    def __call__(self, ip_to_mac) -> None:
        raise NotImplementedError
