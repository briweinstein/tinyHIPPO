#! /usr/bin/env python3
from scapy.all import TCP, UDP, IP, Ether, ls

suspicious_ports = [21,22,23,2323,25,110,111,135]

# TODO: verify certs, plaintext, check encryption type (md5, wpa, etc)
# TODO: separate sus ports for TCP/UDP?

class Privacy_Analysis:
  def __init__(self, packet):
    self.packet = packet

  def process_packet(self):
    print("Processing packet")
    print(self.packet.src)

    is_TCP = self.packet.haslayer(TCP)
    is_UDP = self.packet.haslayer(UDP)
    # TCP, UDP, or False, based on the above results
    proto_type = TCP if is_TCP else UDP if is_UDP else False

    # If this packet contains a certificate, validate it
    #if packet.something:
      #validate_cert()

    # Scan for using port 80 and the plaintext for privacy leaks
    #print(ls(self.packet))
    if (proto_type != False) and ((self.packet[proto_type].dport == 80) or (self.packet[proto_type].sport == 80)):
      #TODO: send_alert("Sending data over unencrypted port.")
      self.scan_plaintext()

    # Monitor suspicious ports
    print("Monitoring suspicious ports")
    if self.packet[proto_type].dport in suspicious_ports:
      #TODO: send_alert("Suspicious destination port used: " + self.packet[proto_type].dport)
      print("Alert on bad port")

  # Validate a given certificate
  def validate_cert(self):
    print("Validating certificate")

  # Scan the plaintext for privacy leaks
  def scan_plaintext(self):
    print("Scanning plaintext")
    try:
      if (self.packet[proto_type].dport == 80) or (self.packet[proto_type].sport == 80):
        print(self.packet[proto_type].payload)
    except:
      print("plaintext not found")
      print(self.packet[proto_type].payload)
      return
     

