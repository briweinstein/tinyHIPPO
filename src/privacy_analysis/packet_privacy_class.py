#! /usr/bin/env python3
from scapy.all import TCP, UDP, IP, Ether, ls
import os
<<<<<<< HEAD
from dashboard.alerts.alert import alert
=======
>>>>>>> 175f750... rebased, moved to src

suspicious_ports = [21,22,23,2323,25,110,111,135]

# TODO: plaintext
# TODO: separate sus ports for TCP/UDP?

class Privacy_Analysis_Packet:
  def __init__(self, packet):
    self.packet = packet

  def process_packet(self):
    print("Processing packet")
    print(self.packet.src)

    is_TCP = self.packet.haslayer(TCP)
    is_UDP = self.packet.haslayer(UDP)

    # Perform TCP and UDP checks
    if is_TCP or is_UDP:
      proto_type = TCP if is_TCP else UDP
      print(proto_type)

      # Scan for using port 80 and the plaintext for privacy leaks
      #print(ls(self.packet))
      if (self.packet[proto_type].dport == 80) or (self.packet[proto_type].sport == 80):
<<<<<<< HEAD
        Alert
        #TODO: send_alert("Sending data over unencrypted port.")
        self.__scan_plaintext()
=======
        #TODO: send_alert("Sending data over unencrypted port.")
        self.scan_plaintext()
>>>>>>> 175f750... rebased, moved to src

      # Monitor suspicious ports
      print("Monitoring suspicious ports")
      if self.packet[proto_type].dport in suspicious_ports:
        #TODO: send_alert("Suspicious destination port used: " + self.packet[proto_type].dport)
        print("Alert on bad port")


<<<<<<< HEAD
  ##############################################################################################
  ### Private Helper Methods
  ##############################################################################################
=======
##############################################################################################
### Private Helper Methods
##############################################################################################
>>>>>>> 175f750... rebased, moved to src

  # Scan the plaintext for privacy leaks
  def __scan_plaintext(self):
    print("Scanning plaintext")
    try:
      if (self.packet[proto_type].dport == 80) or (self.packet[proto_type].sport == 80):
        print(self.packet[proto_type].payload)
    except:
      print("plaintext not found")
      print(self.packet[proto_type].payload)
      return
     

