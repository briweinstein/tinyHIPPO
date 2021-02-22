# Packet Inspection
## How to convert hex to scapy package
The packet sniffing script exports packets to files as a hex, which saves space and allows the other scripts to pull any necessary data from the packet later. To reverse the packet from hex form back to a packet, read the hex from the file and perform the following operation on it:
```
from scapy.all import Ether
packet = Ether(bytes.fromhex(packet_hex))
```

## Show the packet's content
Below are two interesting scapy commands to show a packet's content:
```
from scapy.utils import hexdump
packet.show()
hexdump(packet)
```

## Notes
The filename for a packet will be the time it was created, under the "incoming" or "outgoing" folder in the packets folder. If the packet's destination was a specified IoT device, the file will be in the "incoming" folder, and vice versa.

## Future TODOs
1) Set the count of the packets to sniff to 0 before adding it to the OpenWrt package
2) Remove the MAC address validation from the script, it will likely be performed when the user inputs them, before the config file is created
