# CodeAlpha_NetworkSniffer

A network packet sniffer built during the **CodeAlpha Cyber Security Internship** (Task 1).
It captures live network traffic and breaks down each packet — source/destination,
protocol, ports, and payload — in both a command-line and a Wireshark-style GUI version.

## Features
- Live packet capture using **Scapy**, with **Socket** for port→service and hostname resolution
- Protocol decoding for TCP, UDP, ICMP, ARP, DNS, and HTTP
- Port-to-service names (443/https, 53/domain, 22/ssh, ...)
- Host discovery — ARP-scan your own subnet to list devices
- Live statistics: top talkers, top services, conversations, per-host bandwidth
- Save captures to `.pcap` for Wireshark
- GUI edition: interface dropdown, colour-coded packet table, per-packet detail view

## Requirements
- Python 3
- Scapy: `sudo apt install python3-scapy` (Kali/Debian) or `pip install scapy`
- Tkinter (GUI only): `sudo apt install python3-tk`

## Usage
Packet capture needs root privileges.

```bash
# CLI version
sudo python3 network_sniffer.py -i eth0            # sniff on an interface
sudo python3 network_sniffer.py -i eth0 -c 50      # capture 50 packets
sudo python3 network_sniffer.py --scan             # discover hosts on your subnet
sudo python3 network_sniffer.py -i eth0 -w out.pcap  # save to pcap

# GUI version
sudo python3 network_sniffer_gui.py
```

## Ethical Notice
This tool is for educational use on networks you own or are explicitly authorised
to monitor. Unauthorised interception of network traffic is illegal.

## Author
Hamas Ahmad Furqan 
