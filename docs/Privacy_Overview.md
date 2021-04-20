# Privacy Protection System Overview
The privacy protection system views the packets, system, and individual devices as a whole: the three components work 
together. However, each component is individually vulnerable to attacks, something the privacy protection system aims 
to defend against. By performing the privacy analysis in these three areas, we can report to the user with confidence 
that we are monitoring their network.

## Packet Privacy Analysis
The privacy analysis for individual packets is an integral part of the tinyHIPPO system. The analysis checks for 
potential emails, credit cards, social security numbers, and keywords viewed in the packets sent to and from the IoT 
devices. This analysis protects against the IoT device leaking user data or suspicious requests being sent to the 
device. Additionally, the packet privacy analysis checks for use of suspicious ports in individual packets.

## System Privacy Analysis
The privacy analysis for system security configurations looks at the router's security. Even if there are no attackers 
targeting the IoT devices, weak system security configurations leave everything on the router vulnerable for an attack. 
While OpenWrt is designed to be default-secure, there are still aspects where a user can implement bad security 
practices. This analysis alerts on a root password not set, weak encryption ciphers used, insecure remote access 
protocols, and packages that need to be upgraded.

## IoT Device Privacy Analysis with Scanning
The privacy analysis for individual IoT devices is performed with scanning, which determines which ports are open on 
each IoT device. This will allow the user to see in real time how their IoT devices act on the network and alert on any 
suspicious ports that are open.

## System Flow
When the tinyHIPPO system is started, the system and scanning analyses are run and alerted accordingly. Since these 
configurations are less likely to be changed often, the alerting does not need to occur regularly. The individual 
packet analysis is done on every packet, which occurs at the same time that the IDS inspects the packets. Alerts are 
generated as necessary and sent to the dashboard for the user to view.
