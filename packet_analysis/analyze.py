#!/usr/bin/python
import os
import sys

sys.path.insert(0, os.path.abspath(".."))
import re
import time
from pathlib import Path
from scapy.all import sniff
from scapy.all import Packet

from packet_analysis.sql.dao import *
from packet_analysis.sql.dao import sqlObject
from packet_analysis.sql.csv.csv_builder import CSVBuilder
from packet_analysis.sql.sql_insert import table_bindings, create_connection, bulk_insert



# TODO: A formal list
todo = ("\n"
        "    1) Use the signature models for anomaly detection to pick n choose the required data\n"
        "    2) Build and populate a SQL database structure to house this data\n"
        "    3) Build an analysis program to extract equations from the database\n"
        "    4) Build signatures from this equation\n"
        "    5) Finish the engine's implementation of these signatures\n"
        "    6) Tweak as necessary\n")

csv_collection = None

def analyze_pcap_file(path: str):
    global csv_collection
    csv_collection = CSVBuilder()
    correct_path = Path(path)
    print("*" * 50)
    print("Sniffing packets of: " + str(correct_path))
    sniff(offline=str(correct_path), prn=alert_pkt, store=False)


def pull_layer(layer):
    class_desc = str(layer).split('.')
    return re.match(r"^[^']*", class_desc[len(class_desc) - 1]).group(0)


def deconstruct_packet(pkt_type: str, pkt: Packet) -> sqlObject:
    switcher = {
        "ARP": lambda p: arp.ARP(p),
        "DHCP": lambda p: dhcp.DHCP(p),
        "DNS": lambda p: dns.DNS(p),
        "EAPOL": lambda p: eapol.EAPOL(p),
        "Ethernet": lambda p: ethernet.Ethernet(p),
        "IP": lambda p: ip.IP(p),
        "NTPHeader": lambda p: ntp.NTPHeader(p),
        "TCP": lambda p: tcp.TCP(p),
        "UDP": lambda p: udp.UDP(p),
    }

    return switcher[pkt_type](pkt)


def alert_pkt(pkt: Packet):
    # Layer separation
    pkt_layers = pkt.layers()

    # MAC Address Parsing
    # TODO: Allow for MAC address filtering (Current PCAPs don't require it since all devices are IOT)

    # Pull out the outer most layer of the PKT
    str_layer = pull_layer(pkt.layers()[-1])
    if str_layer == "Raw":
        str_layer = pull_layer(pkt.layers()[-2])

    if str_layer in table_bindings.keys():
        sql_dao = deconstruct_packet(str_layer, pkt)
        csv_collection.add_entry(str_layer, sql_dao.csv())

def main(argv):
    # Make sure a file is specified
    if len(argv) < 1:
        print("No PCAP files specified, please run the command "
              "./pcap_analysis [path-to-file] [path-to-another-file] ...")
        return -1

    first_time = time.time()
    print("*" * 50)
    conn = create_connection("D:/Semester 6/Capstone/DB/analysis.db")

    for path in argv[1:]:
        analyze_pcap_file(path)
        print("*" * 50)
        print("Inserting int SQL-DB")
        bulk_insert(conn, csv_collection.sql_objects)

    elapsed_time = time.time() - first_time
    print("*" * 50)
    print("Elapsed Time:")
    print("-" * 50)
    print("Hours:   " + str((elapsed_time / 3600) % 86400))
    print("Minutes: " + str((elapsed_time / 60) % 3600))
    print("Seconds: " + str(elapsed_time % 60))

    return 1


if __name__ == "__main__":
    main(sys.argv)
