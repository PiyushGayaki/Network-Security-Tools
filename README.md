# Network Security Tools

This repository contains a suite of advanced Python-based tools for network security testing. These tools cover tasks such as ARP spoofing, DNS spoofing, port scanning, packet sniffing, and network scanning. Each tool is designed to be efficient, dynamic, and easy to use, allowing penetration testers and security researchers to perform various network attacks and scans.

---

## Tools Included

1. **ARP Spoofer**  
   Perform ARP spoofing to enable Man-in-the-Middle (MITM) attacks on a local network.
   
2. **DNS Spoofer**  
   Intercept DNS queries and redirect users to a malicious IP by modifying DNS responses.
   
3. **Simple Port Scanner with Threading**  
   Efficiently scan a range of ports on a target host using multithreading.
   
4. **Scapy Packet Sniffer**  
   Sniff HTTP traffic on a network interface and capture raw data from TCP connections.
   
5. **Network Scanner**  
   Discover active devices on the local network using ARP and ICMP requests.

---

## Installation

To use these tools, you must have Python 3 installed. You can install the required dependencies by running:

```bash
pip install scapy netfilterqueue colorama
```

For some tools (e.g., ARP Spoofer and DNS Spoofer), you might need administrative/root privileges. Ensure you run these scripts with `sudo` or as an administrator.

---

## Usage

Each tool is a standalone Python script that accepts command-line arguments. Below are examples of how to use each tool:

### 1. ARP Spoofer

This tool spoofs ARP responses, tricking devices into sending their traffic through the attacker's machine.

#### Usage:
```bash
sudo python3 arp_spoofer.py <target_ip> <host_ip>
```

- `target_ip`: The IP address of the target device (e.g., a victim's computer).
- `host_ip`: The IP address of the host device (e.g., a router).

#### Example:
```bash
sudo python3 arp_spoofer.py 192.168.1.10 192.168.1.1
```

### 2. DNS Spoofer

Intercept DNS requests and spoof responses to redirect traffic to a malicious IP address.

#### Usage:
```bash
sudo python3 dns_spoofer.py <domain> <spoofed_ip>
```

- `domain`: The domain name to spoof (e.g., `example.com`).
- `spoofed_ip`: The IP address to which the target should be redirected.

#### Example:
```bash
sudo python3 dns_spoofer.py example.com 192.168.1.100
```

### 3. Simple Port Scanner with Threading

Efficiently scan a range of ports on a target host using multiple threads for faster results.

#### Usage:
```bash
python3 simple_port_scanner.py -t <target> -s <start_port> -e <end_port> -n <threads> [-o <output_file>] [-v]
```

- `-t`: Target IP or hostname.
- `-s`: Start port number.
- `-e`: End port number.
- `-n`: Number of threads (default: 100).
- `-o`: (Optional) Output file to save results.
- `-v`: (Optional) Enable verbose output.

#### Example:
```bash
python3 simple_port_scanner.py -t example.com -s 20 -e 1024 -n 50 -o results.txt -v
```

### 4. Scapy Packet Sniffer

Sniff network traffic on a specified interface and log TCP/HTTP data. You can optionally save the output to a file.

#### Usage:
```bash
sudo python3 Scapy_packet_sniffer.py <interface> [output_file]
```

- `interface`: The network interface to sniff on (e.g., `eth0`).
- `output_file`: (Optional) File to save the captured data.

#### Example:
```bash
sudo python3 Scapy_packet_sniffer.py eth0 output.txt
```

### 5. Network Scanner

Scan the local network to discover active hosts using ARP and ICMP.

#### Usage:
```bash
python3 network_scanner.py <target_network>
```

- `target_network`: The network range to scan (e.g., `192.168.1.0/24`).

#### Example:
```bash
python3 network_scanner.py 192.168.1.0/24
```

---

## Dependencies

All tools use the following Python libraries:
- [Scapy](https://scapy.net/) - A powerful Python library for network packet manipulation.
- [netfilterqueue](https://github.com/kti/python-netfilterqueue) - Library for working with NetfilterQueue in Python.
- [colorama](https://pypi.org/project/colorama/) - Library for cross-platform colored terminal text.

Install dependencies with:
```bash
pip install scapy netfilterqueue colorama
```

Some tools (like ARP and DNS Spoofer) may require iptables configuration. Make sure you have the proper firewall rules in place.

---

## Contributing

Contributions to enhance or extend these tools are welcome! Please fork this repository, make your changes, and submit a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Disclaimer

These tools are provided for educational purposes only. Use them responsibly and only on networks or devices where you have permission to do so. The authors are not responsible for any misuse or damage caused by these tools.

---

## Contact

Feel free to contact me for any questions or feedback. You can reach me via GitHub issues or email.

---

## Roadmap

Future improvements:
- Integration with a web-based dashboard for real-time monitoring.
- Add more protocols for sniffing (e.g., DNS, FTP).
- Extend ARP and DNS spoofers with more advanced attack scenarios.
- Add logging and reporting features for each tool.
