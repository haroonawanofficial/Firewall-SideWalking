import random
import socket
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.ssl_tls import *
from colorama import Fore, Style, init
from tabulate import tabulate
import ipaddress
from time import sleep

# Initialize colorama
init(autoreset=True)

# Setup logging
logging.basicConfig(filename='scan_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define evasion techniques
evasion_techniques = ["Randomized Source IP", "Randomized Payload", "Variable Packet Sizes", "Mutated Payloads"]

# Define scan functions
def reverse_ip_scan(target_ip, target_port):
    packet = IP(dst=target_ip, src=target_ip)/ICMP()
    return perform_scan("Reverse IP Scan", packet, target_ip, target_port)

def custom_ip_options_scan(target_ip, target_port):
    packet = IP(dst=target_ip, options=[IPOption(b'\x82\x04\x00\x00')])/ICMP()
    return perform_scan("Custom IP Options Scan", packet, target_ip, target_port)

def icmp_source_quench_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/ICMP(type=4)
    return perform_scan("ICMP Source Quench Scan", packet, target_ip, target_port)

def custom_tcp_option_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, options=[(0x42, b'\x01\x02\x03\x04')])
    return perform_scan("Custom TCP Option Scan", packet, target_ip, target_port)

def custom_payload_tcp_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port)/Raw(load="CustomPayload")
    return perform_scan("Custom Payload TCP Scan", packet, target_ip, target_port)

def tcp_syn_scan(target_ip, target_port, spoofed_ip=None):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    return perform_scan("TCP SYN Scan", packet, target_ip, target_port, spoofed_ip)

def mutated_payload_scan(target_ip, target_port):
    payload = "CustomPayload" + str(random.randint(0, 1000000))
    packet = IP(dst=target_ip)/TCP(dport=target_port)/Raw(load=payload)
    return perform_scan("Mutated Payload Scan", packet, target_ip, target_port)

def ssl_encrypted_scan(target_ip, target_port):
    tls_handshake = TLSClientHello()
    packet = IP(dst=target_ip)/TCP(dport=target_port)/tls_handshake
    return perform_scan("SSL Encrypted Scan", packet, target_ip, target_port)

# Define a function to perform a scan
def perform_scan(scan_type, packet, target_ip, target_port, spoofed_ip=None):
    if spoofed_ip:
        packet[IP].src = spoofed_ip
    response = sr1(packet, timeout=1, verbose=False)
    
    # Determine the result based on the response
    if response:
        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                scan_result = "Open"
            elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                scan_result = "Closed"
            else:
                scan_result = "Filtered"
        elif response.haslayer(ICMP):
            if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]:
                scan_result = "Filtered"
            else:
                scan_result = "Open"
        else:
            scan_result = "Filtered"
    else:
        scan_result = "Filtered"
        
    firewall_detected = "Yes" if scan_result == "Filtered" else "No"
    return [scan_type, target_ip, target_port, scan_result, firewall_detected]

# Define a function to resolve target
def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target

# Define a function to parse arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced Network Scanner for Security Professionals")
    parser.add_argument('--target', required=True, help='Target IP, domain, or CIDR notation')
    parser.add_argument('--ports', required=True, help='Comma-separated list of target ports')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads for scanning')
    parser.add_argument('--spoof', help='IP address to spoof')
    parser.add_argument('--techniques', nargs='+', choices=['reverse_ip', 'custom_ip', 'icmp_source_quench', 'custom_tcp_option', 'custom_payload', 'mutated_payload', 'ssl_encrypted', 'all'], help='Scanning techniques to use')
    parser.add_argument('--stealth', action='store_true', help='Mimic legal user behavior or use advanced stealth techniques')
    parser.add_argument('--usetcpsyn', action='store_true', help='Use TCP SYN scan to detect the presence of a firewall')
    return parser.parse_args()

# Define a function to print scan results
def print_scan_results(scan_results):
    headers = ["Scan Type", "IP", "Port", "Result", "Firewall Detected"]
    table = [[Fore.GREEN + str(item[0]) + Style.RESET_ALL, item[1], item[2], item[3], item[4]] for item in scan_results]
    print(tabulate(table, headers=headers, tablefmt="grid"))

# Define a function to print infiltration methods
def print_infiltration_methods():
    methods = [
        ["TCP SYN Scan", "Layer 4", "Detects open ports and firewall presence", "Network Commands"],
        ["Custom TCP Option Scan", "Layer 4", "Bypasses some filters with unusual TCP options", "Network Commands"],
        ["Custom Payload TCP Scan", "Layer 4", "Bypasses some filters with non-standard payloads", "Network Commands"],
        ["ICMP Source Quench Scan", "Layer 3", "Bypasses some filters with ICMP packets", "Network Commands"],
        ["Reverse IP Scan", "Layer 3", "Confuses detection systems with source and destination IP the same", "Network Commands"],
        ["Custom IP Options Scan", "Layer 3", "Bypasses filters with custom IP options", "Network Commands"],
        ["Mutated Payload Scan", "Layer 4", "Confuses security systems with varying payloads", "Network Commands"],
        ["SSL Encrypted Scan", "Layer 4", "Looks like legitimate SSL traffic", "Network Commands"],
    ]
    headers = ["Infiltration Method", "Layer", "Use Case", "Supports"]
    print(tabulate(methods, headers=headers, tablefmt="grid"))

# Define a function to generate target IPs from CIDR
def generate_target_ips(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [cidr]

# Define a function for stealth scanning
def stealth_scan(target, ports, spoof_ip=None, delay=1.0):
    for port in ports:
        packet = IP(dst=target, src=spoof_ip if spoof_ip else None)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            logging.info(f"Port {port} on {target} is open.")
            if spoof_ip is None:  # Only if not spoofing, to avoid stateful firewall detection
                send(IP(dst=target)/TCP(dport=port, flags="A"), verbose=False)
        sleep(delay)

# Define the main function
def main():
    args = parse_arguments()
    targets = []
    if '/' in args.target:
        targets = generate_target_ips(args.target)
    else:
        targets = [resolve_target(t) for t in args.target.split(',')]
    ports = [int(p) for p in args.ports.split(',')]

    scan_results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for target in targets:
            for port in ports:
                if args.techniques:
                    if 'all' in args.techniques or 'reverse_ip' in args.techniques:
                        futures.append(executor.submit(reverse_ip_scan, target, port))
                    if 'all' in args.techniques or 'custom_ip' in args.techniques:
                        futures.append(executor.submit(custom_ip_options_scan, target, port))
                    if 'all' in args.techniques or 'icmp_source_quench' in args.techniques:
                        futures.append(executor.submit(icmp_source_quench_scan, target, port))
                    if 'all' in args.techniques or 'custom_tcp_option' in args.techniques:
                        futures.append(executor.submit(custom_tcp_option_scan, target, port))
                    if 'all' in args.techniques or 'custom_payload' in args.techniques:
                        futures.append(executor.submit(custom_payload_tcp_scan, target, port))
                    if 'all' in args.techniques or 'mutated_payload' in args.techniques:
                        futures.append(executor.submit(mutated_payload_scan, target, port))
                    if 'all' in args.techniques or 'ssl_encrypted' in args.techniques:
                        futures.append(executor.submit(ssl_encrypted_scan, target, port))
                if args.usetcpsyn:
                    futures.append(executor.submit(tcp_syn_scan, target, port, args.spoof))
                if args.stealth:
                    stealth_scan(target, ports, args.spoof)

        for future in futures:
            result = future.result()
            if result not in scan_results:
                scan_results.append(result)

    print_scan_results(scan_results)
    print_infiltration_methods()
    logging.info("Scan completed")

if __name__ == "__main__":
    main()
