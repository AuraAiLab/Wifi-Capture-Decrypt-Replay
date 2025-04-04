#scapy-decrypt-clean

#!/usr/bin/env python3

import os
import subprocess
import logging
from scapy.all import *
from tqdm import tqdm

# Configuration
input_pcap_file = "sample2.pcap"  # Replace with your input .pcap file
decrypted_pcap_file = "decrypted_capture.pcap"
cleaned_pcap_file = "cleaned-capture.pcap"

ssid = "xxxxx"  # Replace with your SSID
password = "xxxxx"  # Replace with your WPA/WPA2 password

source_mac = "d8:3a:dd:c3:24:f2"  # Source MAC for cleaning
source_ip = "192.168.10.250"      # Source IP for cleaning
target_mac = "d4:3d:39:e2:fc:76"  # Target MAC for cleaning
target_ip = "192.168.10.74"       # Target IP for cleaning

# Setup logging for debugging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def decrypt_with_airdecap(input_pcap, ssid, password):
    """Decrypt packets using airdecap-ng and gather host MAC addresses."""
    logging.info("Starting decryption with airdecap-ng...")

    try:
        # Build the airdecap-ng command
        command = [
            "airdecap-ng",
            "-e", ssid,
            "-p", password,
            input_pcap
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)

        # Log the output of airdecap-ng
        if result.returncode == 0:
            logging.info(result.stdout)
        else:
            logging.error(f"airdecap-ng failed with error: {result.stderr}")
            exit(1)

        # Determine the decrypted file name
        decrypted_pcap = input_pcap.replace(".pcap", "-dec.pcap")
        if not os.path.exists(decrypted_pcap):
            logging.critical(f"Decrypted file {decrypted_pcap} was not created. Check the input .pcap file or credentials.")
            exit(1)

        # Extract host MAC addresses from the Ether layer in the decrypted pcap
        host_macs = set()
        with PcapReader(decrypted_pcap) as packets:
            for pkt in packets:
                if pkt.haslayer(Ether):
                    if pkt[Ether].src:  # Source MAC
                        host_macs.add(pkt[Ether].src)
                    if pkt[Ether].dst:  # Destination MAC
                        host_macs.add(pkt[Ether].dst)

        logging.info(f"Decryption completed. Decrypted packets saved to {decrypted_pcap}.")
        if host_macs:
            logging.info(f"Decrypted host MAC addresses: {', '.join(host_macs)}")
        else:
            logging.warning("No MAC addresses were extracted from the decrypted packets.")
        return decrypted_pcap, host_macs

    except Exception as e:
        logging.critical(f"Error during decryption: {e}")
        exit(1)


def clean_packets(input_pcap_file, output_pcap_file):
    """Clean decrypted packets and save cleaned output."""
    logging.info(f"Starting to process file: {input_pcap_file}")

    try:
        total_packets = 0
        processed_packets = 0
        skipped_packets = 0
        error_packets = 0
        cleaned_packets = []

        # Use PcapReader with tqdm for progress tracking
        with PcapReader(input_pcap_file) as pcap_reader, tqdm(desc="Processing Packets", unit="pkt") as pbar:
            for pkt in pcap_reader:
                total_packets += 1
                try:
                    # Skip packets that are not Ethernet or convertible 802.11 data frames
                    if not pkt.haslayer(Ether):
                        if pkt.haslayer(Dot11):
                            # Skip management or control frames
                            if pkt.type == 0:  # Management frames (e.g., beacons, probes)
                                skipped_packets += 1
                                pbar.update(1)
                                continue
                            if pkt.type == 1:  # Control frames (e.g., RTS/CTS)
                                skipped_packets += 1
                                pbar.update(1)
                                continue
                            if pkt.type == 2:  # Data frames
                                # Convert to Ethernet
                                try:
                                    pkt = RadioTap() / Ether(bytes(pkt[Dot11]))
                                    processed_packets += 1
                                except Exception as e:
                                    logging.error(f"Error converting 802.11 frame: {e}")
                                    error_packets += 1
                                    pbar.update(1)
                                    continue
                        else:
                            skipped_packets += 1
                            pbar.update(1)
                            continue

                    # Handle SSDP (Multicast) Packets
                    if pkt.haslayer(IP) and pkt[IP].dst == "239.255.255.250":
                        pkt[Ether].dst = "01:00:5e:ff:ff:fa"  # Set multicast MAC
                        pkt[IP].dst = "239.255.255.250"      # Ensure multicast IP
                        pkt[Ether].src = source_mac          # Fix source MAC
                        pkt[IP].src = source_ip              # Fix source IP
                    else:
                        # Fix MAC addresses for non-multicast packets
                        if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":  # Broadcast traffic
                            pkt[Ether].src = source_mac
                        else:  # Unicast traffic
                            pkt[Ether].dst = target_mac

                        # Fix source MAC and IP
                        pkt[Ether].src = source_mac
                        if pkt.haslayer(IP):
                            pkt[IP].src = source_ip
                            pkt[IP].dst = target_ip

                    # Fix TTL
                    if pkt.haslayer(IP):
                        pkt[IP].ttl = 128  # Set TTL to a standard value

                    # Fix checksums
                    if pkt.haslayer(IP):
                        del pkt[IP].chksum
                    if pkt.haslayer(TCP):
                        del pkt[TCP].chksum
                    if pkt.haslayer(UDP):
                        del pkt[UDP].chksum

                    # Rebuild packet
                    pkt = pkt.__class__(bytes(pkt))
                    cleaned_packets.append(pkt)

                    # Save in batches to avoid large memory usage
                    if len(cleaned_packets) >= 1000:
                        wrpcap(output_pcap_file, cleaned_packets, append=True)
                        cleaned_packets.clear()

                except Exception as e:
                    error_packets += 1
                    logging.error(f"Error processing packet: {e}")

                # Update progress bar
                pbar.set_postfix({
                    "Processed": processed_packets,
                    "Skipped": skipped_packets,
                    "Errors": error_packets
                })
                pbar.update(1)

        # Save remaining packets
        if cleaned_packets:
            wrpcap(output_pcap_file, cleaned_packets, append=True)

        # Print final statistics
        logging.info(f"Total packets: {total_packets}")
        logging.info(f"Processed packets: {processed_packets}")
        logging.info(f"Skipped packets: {skipped_packets}")
        logging.info(f"Error packets: {error_packets}")
        logging.info(f"Cleaned packets saved to {output_pcap_file}")

    except Exception as e:
        logging.critical(f"Critical error during processing: {e}")


if __name__ == "__main__":
    try:
        logging.info("Step 1: Decrypting Packets...")
        decrypted_pcap_file, host_macs = decrypt_with_airdecap(input_pcap_file, ssid, password)

        logging.info("Step 2: Cleaning Decrypted Packets...")
        clean_packets(decrypted_pcap_file, cleaned_pcap_file)
    except KeyboardInterrupt:
        logging.warning("Process stopped by user.")

