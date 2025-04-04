# Wireless Packet Capture & Replay

A toolkit for capturing, decrypting, cleaning, and replaying wireless network packets using Scapy and related tools.

## Overview

This repository contains Python scripts for working with wireless packet captures, with a focus on decrypting, cleaning, and replaying packet captures (pcap files). The tools are built using Scapy, a powerful Python-based interactive packet manipulation program.

## Scripts

### 1. scapy-decrypt-clean.py

This script performs two main functions:
- **Decryption**: Uses `airdecap-ng` to decrypt wireless packets from a WPA/WPA2 protected network
- **Cleaning**: Processes the decrypted packets to make them suitable for replay by:
  - Converting 802.11 frames to Ethernet frames
  - Fixing MAC and IP addresses
  - Handling multicast and broadcast traffic
  - Repairing packet checksums and TTL values

### 2. Scapy-send-loop.py

A simple script that:
- Loads packets from a cleaned pcap file
- Validates packet sending using tcpdump
- Sends packets in a continuous loop with progress tracking

### 3. scapy-send-loop-ratesConfig.py

An enhanced version of the send-loop script that adds configurable packet transmission rates:
- **pcap**: Uses original pcap timing
- **typical**: Sends at a typical wireless rate (1000 PPS)
- **fast**: Sends at a higher rate (10000 PPS)

## Requirements

- Python 3
- Scapy
- tqdm (for progress tracking)
- aircrack-ng suite (for airdecap-ng)
- tcpdump

## Usage

1. **Decrypt and Clean Packets**:
   ```
   python scapy-decrypt-clean.py
   ```
   (Update the script with your SSID, password, and MAC/IP addresses)

2. **Replay Packets**:
   ```
   python Scapy-send-loop.py
   ```
   or with configurable rates:
   ```
   python scapy-send-loop-ratesConfig.py
   ```
   (Update the sending interface in the scripts as needed)

## Notes

- These scripts are designed to work with wireless packet captures
- The decryption process requires the correct SSID and password
- For proper replay, you may need to adjust the source and target MAC/IP addresses in the scripts
