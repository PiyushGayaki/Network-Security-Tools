#!/usr/bin/env python3
from scapy.all import srp, ARP, Ether, IP, ICMP
import sys

# Main program to scan the network
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 network_scanner.py <target_network>")
        sys.exit(1)

    target_network = sys.argv[1]  # Network range (e.g., 192.168.1.0/24)

    online_hosts = []

    # ARP request to discover active hosts on the network
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=target_network)
    result = srp(ether / arp, timeout=2, verbose=0)

    answered = result[0]
    for sent, received in answered:
        online_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

    print(f"[+] Available hosts on {target_network}:")
    print("IP" + " "*20 + "MAC")
    for host in online_hosts:
        print(f"{host['ip']}\t\t{host['mac']}")

    # Optional ICMP (Ping) test to check additional hosts
    ip_list = [host['ip'] for host in online_hosts]
    for ip in ip_list:
        icmp_probe = IP(dst=ip) / ICMP()
        response = sr1(icmp_probe, timeout=2, verbose=0)
        if response:
            print(f"[+] {ip} is responding to ICMP (Ping)")
