import sys
import os

sys.path.insert(0, os.path.abspath(".."))
import re
import time
import argparse
from pathlib import Path
from scapy.all import sniff
from scapy.all import Packet

from packet_analysis.sql.dao import *
from packet_analysis.sql.dao import sqlObject
from packet_analysis.sql.csv.csv_builder import CSVBuilder
from packet_analysis.sql.sql_helper import table_bindings, create_connection, bulk_insert


def analyze_pcap_file(path: str):
    """
    Method called per PCAP file to collect data
    :param path: Path to the PCAP file
    :return: CSVBuilder object
    """
    csv_collection = CSVBuilder()
    correct_path = Path(path)
    print("*" * 50)
    print("Sniffing packets of: " + str(correct_path))
    sniff(offline=str(correct_path), prn=lambda x: deconstruct_packet(x, csv_collection), store=False)
    return csv_collection


def deconstruct_packet(pkt: Packet, csv_collection) -> sqlObject:
    """
    Deconstructs the packet based on its type.
    :param pkt: The packet object itself
    :param csv_collection: Collection of SQLObjects in CSV form
    :return: sqlObject that can be inserted into the DB
    """
    # Switch statement keyed on pkt_type
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

    for layer in switcher.keys():
        if layer in pkt:
            sql_dao = switcher[layer](pkt)
            csv_collection.add_entry(layer, sql_dao.csv())


def main(argv):
    """
    Entry point for the program, handles arguments as paths to the PCAPs
    :param argv: Arguments for program
    """
    parser = argparse.ArgumentParser(description="Analyzes PCAP information and stores it in a SQL database")
    parser.add_argument("database_path", nargs=1, type=str, help="Path for the database file to export data to")
    parser.add_argument("pcap_paths", nargs='+', type=str, help="Path for the database file to export data to")

    args = parser.parse_args(argv[1:])

    # Start time for the process
    first_time = time.time()
    print("*" * 50)

    # Handle arguments
    conn = create_connection(args.database_path[0])
    paths = args.pcap_paths

    # Loop through files, analyze PCAP and insert in bulk into the DB
    for path in paths:
        try:
            csv_collection = analyze_pcap_file(path)
            bulk_insert(conn, csv_collection.sql_objects)
        except Exception as e:
            print("*" * 50)
            print("Error in processing PCAP: {0}\nMoving forward...".format(e))
            print("*" * 50)

    # Print out time based information
    elapsed_time = time.time() - first_time
    print("*" * 50)
    print("Elapsed Time:")
    print("-" * 50)
    print("Hours:   " + str((elapsed_time / 3600) % 86400))
    print("Minutes: " + str((elapsed_time / 60) % 3600))
    print("Seconds: " + str(elapsed_time % 60))


if __name__ == "__main__":
    main(sys.argv)
