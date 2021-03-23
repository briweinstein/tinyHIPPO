#! /usr/bin/env python3
from src.privacy_analysis.scanning_analysis.scanning_privacy import ScanningPrivacy
from src.dashboard.alerts.alert import Alert, ALERT_TYPE, SEVERITY
from src import run_config
import nmap

# Based off of the top 100 TCP/UDP ports scanned (as of 3/2021), the below ones will be alerted on
# TODO: delete the top 100 ports scanned list before merge and after PR is approved
# Top 100 TCP ports scanned (as of 3/2021):
# 7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,
# 554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,
# 3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001, 6646,7070,8000,8008-8009,8080-8081,
# 8443,8888,9100,9999-10000,32768,49152-49157
ports_allow_tcp = [7, 9, 53, 80, 139, 179, 199, 443, 554, 1433, 1755, 3306, 5000, 5051, 5060, 5432, 6000, 6001, 7070,
                   8000, 8008, 8009, 8080, 8081, 8443, 8888, 10000]
ports_severe_alert_tcp = [20, 21]

# Top 100 UDP ports scanned (as of 3/2021):
# 7,9,17,19,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,427,443,445,497,500,514-515,518,520,593,623,626,631,
# 996-999,1022-1023,1025-1030,1433-1434,1645-1646,1701,1718-1719,1812-1813,1900,2000,2048-2049,2222-2223,3283,3456,3703,
# 4444,4500,5000,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768-32769,32771,32815,33281,49152-49154,49156,
# 49181-49182,49185-49186,49188,49190-49194,49200-49201,65024)
ports_allow_udp = [7, 9, 53, 80, 123, 137, 138, 139, 443, 500, 593, 1433, 1434, 1719, 4500, 5000, 5432, 5060, 9200, 10000]
ports_severe_alert_udp = [69]


class ScanningPrivacyNmapPassive(ScanningPrivacy):
    def __call__(self, ip_to_mac):
        print("Passive scanning")
        ip_list = list(ip_to_mac.keys())
        # Scan
        nm = nmap.PortScanner()
        try:
            results_top = nm.scan(hosts=" ".join(ip_list), arguments="-sT -sU --top-ports 100")
            results_specific = nm.scan(hosts=" ".join(ip_list), arguments="-sT -p 194")
        except Exception as e:
            run_config.log_event.info("Exception raised, passive nmap scan failed: " + str(e))
            return

        # Process TCP and UDP ports, if any
        for ip in list(results_top["scan"].keys()):
            self.__inspect_open_ports(ip, ip_to_mac[ip], results_top["scan"], "tcp", ports_allow_tcp, ports_severe_alert_tcp)
            self.__inspect_open_ports(ip, ip_to_mac[ip], results_top["scan"], "udp", ports_allow_udp, ports_severe_alert_udp)
        for ip in list(results_specific["scan"].keys()):
            self.__inspect_open_ports(ip, ip_to_mac[ip], results_specific["scan"], "tcp", [], [])

    def __inspect_open_ports(self, ip, mac, results, port_type, ports_allow, ports_severe_alert):
        """
        This method inspects the open ports for the given port_type and Alerts if any suspicious open ports are found.
        A severe Alert is generated if any ports in ports_info_severe_alert are found.
        :param ip: The IP being scanned
        :param mac: The MAC corresponding to the IP
        :param results: The ports nmap scan results
        :param port_type: The port type to inspect, either "tcp" or "udp"
        :param ports_allow: The list of allowed ports for this port type
        :param ports_severe_alert: Generates a severe Alert if any of these ports are found open
        :return: Whether the packet came from a spoofed MAC Address
        """
        if port_type in results[ip]:
            for port in results[ip][port_type]:
                if port not in ports_allow:
                    alert_obj = Alert(None, "Suspicious open " + port_type.upper() + " port found: " + str(port) + " on device with MAC address " + mac + ". Further " +
                                      "investigation recommended.", ALERT_TYPE.PRIVACY, SEVERITY.INFO)
                    alert_obj.alert()
                if port in ports_severe_alert:
                    alert_obj = Alert(None, "Very suspicious open " + port_type.upper() + " port found: " + str(port) + " on device with MAC address " + mac +
                                      ". Further investigation required.", ALERT_TYPE.PRIVACY, SEVERITY.ALERT)
                    alert_obj.alert()

