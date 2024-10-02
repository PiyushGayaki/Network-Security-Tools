#!/usr/bin/env python3
"""
Advanced Simple Port Scanner with Threading

This script scans a range of ports on a target host to identify open ports.
It uses multithreading to perform the scan efficiently.

Usage:
    python3 simple_port_scanner.py -t <target> -s <start_port> -e <end_port> -n <threads> [-o <output_file>] [-v]

Example:
    python3 simple_port_scanner.py -t example.com -s 20 -e 1024 -n 100 -o scan_results.txt -v
"""

import socket
import time
import queue
import threading
import argparse
from scapy.all import sr1, IP, TCP, RandShort, send

# Initialize the argument parser for better command-line handling
parser = argparse.ArgumentParser(description="Advanced Simple Port Scanner with Threading")
parser.add_argument("-t", "--target", required=True, help="Target hostname or IP address")
parser.add_argument("-s", "--start_port", type=int, required=True, help="Start port number")
parser.add_argument("-e", "--end_port", type=int, required=True, help="End port number")
parser.add_argument("-n", "--threads", type=int, default=100, help="Number of threads (default: 100)")
parser.add_argument("-o", "--output", help="Output file to save scan results")
parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose output")
args = parser.parse_args()

# Global variables
target = args.target
start_port = args.start_port
end_port = args.end_port
thread_no = args.threads
output_file = args.output
verbose = args.verbose

# Resolve target hostname to IP address
try:
    target_ip = socket.gethostbyname(target)
except socket.gaierror:
    print(f"[-] Host resolution failed for {target}")
    sys.exit(1)

# Queue to hold ports to scan
q = queue.Queue()

# Populate the queue with port numbers for scanning
for port in range(start_port, end_port + 1):
    q.put(port)

# Dictionary to map common ports to services for identification
common_services = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "Microsoft RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "Microsoft-DS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Proxy",
}

# Lock for synchronizing access to the result string
result_lock = threading.Lock()
scan_results = "[+] Port Scan Results:\nPORT\tSTATE\tSERVICE\n"

def get_service(port):
    """
    Returns the service name for a given port.
    If the port is not in the common_services dictionary, returns 'Unknown'.
    """
    return common_services.get(port, "Unknown")

def scan_port(thread_id):
    """
    Worker thread function to scan ports. Uses SYN packets and looks for SYN-ACK responses to detect open ports.
    """
    global scan_results
    while not q.empty():
        port = q.get()
        try:
            if verbose:
                print(f"[Thread {thread_id}] Scanning port {port}...")

            # Send SYN packet and wait for SYN-ACK
            syn_packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags='S')
            response = sr1(syn_packet, timeout=1, verbose=0)

            if response:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:  # SYN-ACK received
                    # Port is open, send RST to close the connection
                    rst_packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags='R')
                    send(rst_packet, verbose=0)

                    service = get_service(port)

                    with result_lock:
                        scan_results += f"{port}\tOPEN\t{service}\n"

                    if verbose:
                        print(f"[+] Port {port} is OPEN ({service})")
                elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST-ACK (port closed)
                    if verbose:
                        print(f"[-] Port {port} is CLOSED")
            else:
                # No response means the port is filtered or closed (timeout)
                if verbose:
                    print(f"[?] Port {port} is FILTERED or CLOSED")

        except Exception as e:
            if verbose:
                print(f"[!] Exception occurred while scanning port {port}: {e}")

        finally:
            q.task_done()

def main():
    """
    Main function to start the port scanning process, creating threads and managing output.
    """
    global scan_results

    print("*" * 50)
    print("Python Advanced Simple Port Scanner with Threading")
    print("*" * 50)
    print(f"Target: {target_ip} ({target})")
    print(f"Port Range: {start_port}-{end_port}")
    print(f"Threads: {thread_no}")
    print("-" * 50)

    # Start timing the scan
    start_time = time.time()

    # Create and start threads for port scanning
    threads = []
    for i in range(thread_no):
        thread = threading.Thread(target=scan_port, args=(i + 1,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Wait for all tasks in the queue to be processed
    q.join()

    # End timing the scan
    end_time = time.time()
    duration = end_time - start_time

    # Print the results
    print("-" * 50)
    print(scan_results)
    print(f"Time taken: {duration:.2f} seconds")

    # Save the results to a file if specified
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(f"Port scan results for target: {target_ip} ({target})\n")
                f.write(f"Port Range: {start_port}-{end_port}\n")
                f.write(f"Threads: {thread_no}\n")
                f.write(f"Time taken: {duration:.2f} seconds\n")
                f.write(scan_results)
            print(f"[+] Results written to {output_file}")
        except Exception as e:
            print(f"[!] Failed to write results to {output_file}: {e}")

if __name__ == "__main__":
    main()
