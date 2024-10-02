# Network Security Tools

This repository contains tools for network security assessments, including ARP spoofing, DNS spoofing, port scanning, and packet sniffing.

## Tools Overview

### 1. ARP Spoofing (`arp_spoofer.py`)
- Spoofs ARP responses to perform man-in-the-middle attacks.
- **Usage**: `python3 arp_spoofer.py`
  
### 2. DNS Spoofing (`dns_spoofer.py`)
- Intercepts DNS requests and sends spoofed DNS responses.
- **Usage**: `sudo python3 dns_spoofer.py`

### 3. Port Scanning
- **Scapy Port Scanner** (`scapy_port_scanner.py`): Uses Scapy to perform SYN scans.
- **Simple Port Scanner** (`simple_port_scanner.py`): Basic port scanner using Python sockets.
- **Usage**: `python3 scapy_port_scanner.py <target> <start_port> <end_port> <threads>`

### 4. Packet Sniffing
- **Scapy Sniffer** (`scapy_sniffer.py`): Sniffs network traffic and extracts data.
- **Scapy Packet Sniffer** (`Scapy_packet_sniffer.py`): Writes captured traffic to an output file.
- **Usage**: `python3 scapy_sniffer.py <interface>`

### 5. Network Scanning (`network_scanner.py`)
- Scans the local network for active hosts and retrieves their IP and MAC addresses.
- **Usage**: `python3 network_scanner.py <target_network>`
