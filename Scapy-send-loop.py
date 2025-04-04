#Scapy-send-loop.py
#this will send the cleaned-capture.pcap file
#!/usr/bin/env python3

#!/usr/bin/env python3

from scapy.all import *
from tqdm import tqdm  # For progress tracking
import subprocess
import time

# Configuration
cleaned_pcap_file = "cleaned-capture.pcap"  # Replace with your cleaned .pcap file
sending_interface = "eth0"

def send_packets_with_validation(cleaned_pcap_file, sending_interface):
    # Load packets from the cleaned pcap file
    packets = rdpcap(cleaned_pcap_file)
    print(f"Loaded {len(packets)} packets from {cleaned_pcap_file}.")

    # Step 1: Validate packet sending using tcpdump
    print("Validating packets on the interface before starting the loop...")
    try:
        # Start tcpdump to capture packets on the specified interface
        tcpdump_proc = subprocess.Popen(
            ["tcpdump", "-i", sending_interface, "-c", "10"],  # Capture 10 packets
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Send a few packets for validation
        for pkt in packets[:10]:
            sendp(pkt, iface=sending_interface, verbose=False)
            time.sleep(0.1)  # Short delay to ensure tcpdump captures packets

        # Wait for tcpdump to finish
        stdout, stderr = tcpdump_proc.communicate()
        if tcpdump_proc.returncode == 0:
            print("Validation successful! Packets are being sent from the interface:")
            print(stdout.decode())
        else:
            print("Validation failed. Check tcpdump output:")
            print(stderr.decode())
            return
    except Exception as e:
        print(f"Error during validation: {e}")
        return

    # Step 2: Send all packets in a loop with progress feedback
    print("Starting to send packets in a loop...")
    try:
        while True:
            with tqdm(total=len(packets), desc="Sending Packets", unit="pkt") as pbar:
                for pkt in packets:
                    sendp(pkt, iface=sending_interface, verbose=False)
                    pbar.update(1)
                    time.sleep(0.001)  # Small delay to avoid overwhelming the network
            print("Loop completed. Restarting...")
    except KeyboardInterrupt:
        print("Packet sending stopped by user.")

if __name__ == "__main__":
    try:
        send_packets_with_validation(cleaned_pcap_file, sending_interface)
    except Exception as e:
        print(f"An error occurred: {e}")

