# tinyHIPPO: Lightweight Home IoT Privacy Protection for OpenWrt
## Overview
The tinyHIPPO package provides an Intrusion Detection System (IDS) and privacy protection system for Internet of Things (IoT) devices that is free and open-source, promoting security of IoT devices for the average user. The pacakge can be compiled by following the instructions in the docs section of this repository and installed on an OpenWrt compatible router.

There were four elements of the system architecture that were considered during the design and implementation process: OpenWrt package design and development, IDS signature and anomaly detection implementation, privacy analysis, and the dashboard and notification system. These elements are described below in their respective sections and all work together to provide security for IoT devices and ease of use for their users.

We measured that on average, tinyHIPPO uses roughly 75MB of RAM when operating and performing all of its operations such as inspected packets and so on. Measurements showed that tinyHIPPO did not affect the performance of the bandwidth whatsoever due to the nature of how the program was designed. It is strongly recommended that a tinyHIPPO user has a router with at least 256MB of RAM to support the package.

## Motiviation
IoT devices have been vulnerable for as long as they have existed. These devices aim to make life easier for a consumer while still being cheap to produce; however, many devices were designed without security in mind. This lack of consideration has harmed the average consumer: they are vulnerable to many attacks and some IoT devices leak sensitive data when they do not implement proper security measures, leaving the users’ information vulnerable.

## System Architecture
### OpenWrt Package Design and Development
The OpenWrt package design and development process is described in detail in the docs section of the project: https://github.com/briweinstein/tinyHIPPO/blob/main/docs/Other_Package_Development_Notes.md#openwrt-package-development-notes and https://github.com/briweinstein/tinyHIPPO/blob/main/docs/Makefile_README.md#package-development--makefile-readme.

### Intrusion Detection System Overview
The IDS generates alerts when IoT devices behave suspiciously on the network. It is described in detail in the docs section of the project: https://github.com/briweinstein/tinyHIPPO/blob/main/docs/IDS_Overview.md#intrusion-detection-system-overview.

### Privacy Protection System Overview
The privacy protection system determines if any IoT devices on the network are privacy risks by analyzing the system configurations, active scanning of the IoT devices, and individual packet inspection. It is described in detail in the docs section of the project: https://github.com/briweinstein/tinyHIPPO/blob/main/docs/Privacy_Overview.md#privacy-protection-system-overview.

### Dashboard
The final element of the system is the dashboard and notification system. This is easily available for the user to view, as it is built into the OpenWrt router dashboard. It is built with Flask instead of Luci because our project codebase is developed in Python. The Luci web server now simply makes requests to the Flask webserver for the dashboard’s content. There are sections added to the existing dashboard for the user to view IDS and privacy alerts, to specify which devices they want to be monitored, and for the user to add their own coefficients to the anomaly detection scheme. The user can choose the devices they would like to monitor based on their MAC address. The system will then only generate alerts for those chosen devices, which can be unselected at any time. The alerts range in severity from low to high and all are shown on the dashboard, but only the high severity alerts will trigger an email being sent to the user.

## IDS and Privacy Protection System Testing
As a whole, the tinyHIPPO system performed well in testing. The various forms of malicious traffic we designed the IDS to detect were found with a high level of accuracy. Both the implementations of the signature based detection and the anomaly detection were able to function as expected. The true positive rate of the IDS was good after adjusting for the payload inspection requirements, at almost 80%. The anomaly detection implementation also proved to be effective at targeting specific traffic rates that could be seen as malicious. Some of the desired features of the IDS were not tested due to some limitations in usage; however, the detection rates would only get better with those features so as a baseline our results were satisfactory.

The privacy testing section evaluated the effectiveness of the system to alert on privacy concerns in router configurations, IoT device scanning results, and individual packet analysis. Due to the deterministic nature of the two former sections, they were solely tested in unit tests. The individual packet analysis results showed a high true positive detection rate and a high false positive detection rate of up to 17.72%, which demonstrates the effectiveness of the system and room for improvement.

## Future Work
The goals for this project were to create a prototype that would be simple for a user to install and other researchers to expand upon. To this end, we believe we have met our goals. However there are still many opportunities  for future work. Our main proposals include the implementation of a Man-in-the-Middle (MitM) attack, a larger external dataset of signatures, active IoT device vulnerability discovery using version numbers, and increased ruleset control for the user.
