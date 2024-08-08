# NG-SideWalk
- NG-SideWalk is an advanced network scanner designed to perform stealthy scans on both internal and public-facing IP networks while evading detection by firewalls, IDS/IPS, and other security measures. The name "NG-SideWalk" reflects the scanner's ability to navigate alongside traditional network security measures, effectively finding pathways (or "sidewalks") into protected networks without triggering alarms.

# Why 
- NG-SideWalk is designed for cybersecurity professionals and researchers who need to perform in-depth network reconnaissance while minimizing the risk of detection. Its advanced capabilities make it a powerful tool for identifying vulnerabilities and potential entry points in both secure and exposed network environments.

## Key Features

# IP Spoofing
- NG-SideWalk can spoof the source IP address, making it appear as though the traffic is coming from a different machine. This helps in avoiding IP-based filtering and tracking.

# Stealth Techniques: 
- The scanner employs various stealth techniques such as;
- Slow Scanning: Spreading the scan over a longer period to avoid rate-based detection systems.
- Fragmentation: Using packet fragmentation to bypass simple packet filters.
- Common Ports: Scanning using destination ports that are commonly open (like 80, 443) to blend in with normal traffic.
- Promiscuous Mode: Capturing packets in promiscuous mode to listen to all the traffic on the network segment without sending additional traffic.
- Layer Manipulation: Dynamically changing packet characteristics to confuse signature-based detection systems.
- Mimicking Normal User Behavior: Using timing and the order of packets to mimic human behavior, making the scanning traffic appear legitimate.
- Advanced Scanning Functions: Includes various sophisticated scanning methods such as:
- Reverse IP Scan: Using ICMP packets with the source set to the target IP.
- Custom IP Options Scan: Utilizing specific IP options to evade detection.
- ICMP Source Quench Scan: Sending ICMP source quench packets.
- Custom TCP Option Scan: Using custom TCP options to bypass firewalls.
- Custom Payload TCP Scan: Sending TCP packets with custom payloads.
- Public and Internal Network Scanning: NG-SideWalk is effective on both internal networks and public-facing IPs, using its evasion techniques to avoid detection and successfully map out network vulnerabilities.

# Recommendation System
The scanner not only detects open ports and services but also recommends the best approaches to infiltrate protected networks based on the scan results.

# Usage
- sudo python ng-sidewalk.py --target example.com,192.168.1.0/24 --ports 80,443 --threads 10 --spoof-ip 203.0.113.1 --rate 2.0

# Output

```bash
2024-08-08 14:30:00 - Number of targets entered: 257
2024-08-08 14:30:00 - Targets: google.com, 192.168.1.0/24
2024-08-08 14:30:00 - Number of ports entered: 2
2024-08-08 14:30:00 - Enumerating Ports: 80, 443

+------------------------+------------------+-------+----------+------------------+---------------------------------------------------+
| Scan Type              | IP               | Port  | Success  | Firewall Detected| Infiltration Method                                 |
+------------------------+------------------+-------+----------+------------------+---------------------------------------------------+
| Reverse IP Scan        | 142.250.64.78    | 80    | Yes      | No               | Use this scan method to infiltrate and bind a virus or port |
| Custom IP Options Scan | 142.250.64.78    | 443   | Yes      | No               | Use this scan method to infiltrate and bind a virus or port |
| ICMP Source Quench Scan| 192.168.1.1      | 80    | No       | Yes              | Try other evasion techniques                        |
| Custom TCP Option Scan | 192.168.1.1      | 443   | No       | Yes              | Try other evasion techniques                        |
| Custom Payload TCP Scan| 192.168.1.2      | 80    | Yes      | No               | Use this scan method to infiltrate and bind a virus or port |
| Stealth Scan           | 192.168.1.3      | 80    | Yes      | No               | Use this scan method to infiltrate and bind a virus or port |
+------------------------+------------------+-------+----------+------------------+---------------------------------------------------+

2024-08-08 14:40:00 - Scanning completed.
```
