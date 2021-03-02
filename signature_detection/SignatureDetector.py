from scapy.layers.l2 import Ether
from email_alerts import test_email
import os
import yara


'''
This class defines the methods that must be defined for Signature Detection for an IoT device to be supported
'''
class SignatureDetector:
    '''
    The below method defines the following attributes required for a "DeviceDetector"
    - mac_address: The MAC address of this DeviceDetector within the network
    - rules: The filepath to the list of YARA rules defined as signatures for this "DeviceDetector"
    '''
    def __init__(self, mac_address:str, rules:str):
        self.mac_address = mac_address
        if os.path.exists(rules):
            self.signature_list = yara.compile(rules)

    '''
    This class method checks the defined signatures for a given packet for this DeviceDetector 
    '''
    def check_signatures(self, packet:str):
        pass



