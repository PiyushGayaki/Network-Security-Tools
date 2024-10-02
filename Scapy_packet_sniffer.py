#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest
from colorama import init, Fore
import sys

# Initialize colorama for colored terminal output
init()

# Define colors for output
red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
yellow = Fore.YELLOW
reset = Fore.RESET

# Function to sniff packets on a specified interface and write output to a file
def sniff_packets(iface, output_file=None):
    if output_file:
        # Open file to write packet data
        with open(output_file, 'w') as f:
            sys.stdout = f  # Redirect output to file
            sniff(filter='tcp', prn=process_packet, iface=iface, store=False)
    else:
        sniff(filter='tcp', prn=process_packet, iface=iface, store=False)

# Function to process each packet captured
def process_packet(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        print(f"{blue}[+] {src_ip} is using port {src_port} to connect to {dst_ip} at port {dst_port}{reset}")

    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()
        print(f"{green}[+] {src_ip} is making an HTTP request to {url} with method {method}{reset}")

        if packet.haslayer(Raw):
            print(f"{red}[+] Useful raw data: {packet.getlayer(Raw).load.decode(errors='ignore')}{reset}")

# Main program execution
if __name__ == "__main__":
    if len(sys.argv) not in [2, 3]:
        print("Usage: python3 Scapy_packet_sniffer.py <interface> [output_file]")
        sys.exit(1)

    iface = sys.argv[1]  # Network interface to sniff on
    output_file = sys.argv[2] if len(sys.argv) == 3 else None

    sniff_packets(iface, output_file)
