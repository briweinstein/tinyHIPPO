# Intrusion Detection System Overview
The IDS implementation has two key components: signature development and anomaly detection. These parts work together 
to alert on suspicious activity coming in and out of the router to the IoT devices. While the tinyHIPPO system is 
installed with default signatures and anomaly detection rules, they can be customized using the script to create new 
algorithms.

## Signatures
The signature development was based on protocols, ports, origin IP, destination IP, and content for incoming and 
outgoing encrypted traffic. Currently, there are signatures to detect MAC address spoofing and communication with 
malicious IP addresses. The detection of communication with these malicious IP addresses leverages free APIs such as 
VirusTotal.

## Anomaly Detection
The second component of the IDS implementation is anomaly detection, where traffic is monitored for unusual spikes in 
the amount of packets sent. If packets are sent at an unusual time, an alert will be generated to notify the user that 
potentially malicious traffic is coming from their IoT device. Such traffic could indicate jobs carried out by devices 
in a botnet, which can use significant bandwidth. We also take into account that firmware updates will also constitute 
unusually high traffic at a potentially unusual time, and we do not alert on these updates.

## Algorithms
Algorithms are a key element of the tinyHIPPO system. Due to the vast differences in IoT devices across the field, we 
have provided a customizable element of the system: algorithm creation tailored to a user's IoT device setup. These 
algorithms are fed pcap data by the user, and create algorithms to alert on suspicious behavior based on the input 
data. This setup is explained further in the "User_Customizing_Overview.md" file.

## System Flow
When the tinyHIPPO system is started, the signatures and anomaly detection rules are called on every packet. Alerts are 
generated as necessary and sent to the dashboard for the user to view.
