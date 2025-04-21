# PacketWarden

**PacketWarden** is a high-performance, C-based Intrusion Detection System (IDS) inspired by Snort and Suricata. It performs real-time deep packet inspection, matching network traffic against configurable rules to detect malicious activity.

---

## Features

- Fast packet capture using libpcap
- Rule-based matching engine (IP, port, protocol, content)
- Layer 2, 3, and 4 parsing (Ethernet/IP/TCP/UDP)
- Custom rule file format
- Modular multithreaded architecture (coming soon)
- Real-time alert logging

---

## Motivation

PacketWarden was built as a systems-level cybersecurity project to:
- Practice high-performance network programming in C
- Gain deep understanding of packet processing, parsing, and alerting
- Train for real-world SDN and EC2 infrastructure roles

---

## Quick Start

### Prerequisites

- GCC or Clang
- `libpcap` installed (`sudo apt install libpcap-dev` on Debian)
- Linux/macOS (preferably Linux)

### Build

```bash
make


sudo ./packetwarden eth0 rules/rules.conf


alert tcp any any -> any 22 (msg:"SSH brute force")
alert udp any any -> any 53 (msg:"DNS exfiltration")
