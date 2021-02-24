import abc
import scapy
'''
This interface defines the methods that must be defined for Signature Detection for an IoT device to be supported
'''


class DeviceDetectorInterface(metaclass=abc.ABCMeta):

    '''
    The below method defines the following attributes required for a "DeviceDetector"
    - mac_address: The MAC address of this DeviceDetector within the network
    - signature_list: The filepath to the list of YARA rules defined as signatures for this "DeviceDetector"
    - check_signatures: method
    '''
    @classmethod
    def __subclasshook__(cls, subclass):
        return (hasattr(subclass, 'mac_address') and
                hasattr(subclass, 'signature_list') and
                hasattr(subclass, 'check_signatures') and
                callable(subclass.check_signatures) or NotImplemented)

    '''
    This class method checks the defined signatures for a given packet for this DeviceDetector 
    '''
    @abc.abstractmethod
    def check_signatures(self, packet: str):
        raise NotImplementedError