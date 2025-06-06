# PRODIGY_CS_05
A Network Packet Analyser (also known as a packet sniffer or protocol analyser) is a tool or program used to capture, inspect, and analyze data packets that travel over a computer network. It allows users to see the detailed contents of network traffic in real-time or from saved captures.

🌐 Network Packet Analyser – Overview

A Network Packet Analyser (also known as a packet sniffer) is a tool used to monitor and analyze network traffic for troubleshooting, security analysis, and learning purposes.
📌 What It Does

    Captures and logs data packets transmitted over a network.

    Displays packet details such as:

        Source & destination IP addresses

        Port numbers

        Protocols (TCP, UDP, HTTP, etc.)

        Packet payload (data content)

    Helps visualize and understand network communication.

🔧 Key Capabilities

    ✅ Live traffic monitoring

    🔍 Detailed protocol inspection

    🎯 Custom packet filtering

    📈 Traffic stats and performance analysis

    🧪 Debugging & troubleshooting

    🛡️ Security monitoring and forensic investigation

🧰 Popular Tools

    Wireshark – GUI-based packet analysis tool.

    tcpdump – Lightweight CLI-based sniffer.

    Tshark – Terminal version of Wireshark.

⚠️ Ethical Use Reminder

    Only use on networks you are authorized to monitor. Unauthorized packet sniffing is illegal and unethical.
🧪 Example Usage
✅ Sample Output (Captured Packet Info)

Time: 2025-05-13 10:45:32
Source IP: 192.168.1.5
Destination IP: 93.184.216.34
Protocol: TCP
Source Port: 51023
Destination Port: 80
Payload Size: 512 bytes
Data: GET /index.html HTTP/1.1

💻 Example (Python-based CLI Tool)

$ python3 packet_analyser.py
[+] Sniffing started on interface: eth0
[+] Captured Packet:
    Time: 2025-05-13 10:45:32
    Source: 192.168.1.5:51023
    Destination: 93.184.216.34:80
    Protocol: TCP
    Data: GET /index.html HTTP/1.1


