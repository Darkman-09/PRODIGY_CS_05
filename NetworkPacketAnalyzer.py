from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import threading

# Flag to control sniffing
stop_sniffing = False

# File to store captured packet data
log_file = "captured_packets.txt"

def process_packet(packet):
    """Display and log captured packet information."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = "\n--- Packet Captured ---\n"
    output += f"Timestamp       : {timestamp}\n"

    if IP in packet:
        ip_layer = packet[IP]
        output += f"Source IP       : {ip_layer.src}\n"
        output += f"Destination IP  : {ip_layer.dst}\n"
        output += f"Protocol        : {ip_layer.proto}"

        if packet.haslayer(TCP):
            output += " (TCP)\n"
        elif packet.haslayer(UDP):
            output += " (UDP)\n"
        elif packet.haslayer(ICMP):
            output += " (ICMP)\n"
        else:
            output += " (Other)\n"

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                decoded = payload.decode(errors='ignore')
                output += f"Payload         :\n{decoded}\n"
            except:
                output += f"Payload (raw)   : {payload}\n"
    else:
        output += "Non-IP packet captured.\n"

    # Print to terminal
    print(output)

    # Append to file
    with open(log_file, "a", encoding='utf-8') as f:
        f.write(output)

def should_stop(packet):
    """Stop sniffing if global flag is True."""
    return stop_sniffing

def start_sniffer():
    """Start capturing packets."""
    print(f"📡 Capturing packets... Logs will be saved to '{log_file}'\n(Press ENTER to stop)\n")
    sniff(prn=process_packet, stop_filter=should_stop, store=False)

# Start sniffing in a thread
sniffer_thread = threading.Thread(target=start_sniffer)
sniffer_thread.start()

# Wait for user input to stop
input("🛑 >> Press ENTER to stop sniffing...\n")
stop_sniffing = True
sniffer_thread.join()

print(f"✅ Sniffing stopped. Packets saved to '{log_file}'.")