from scapy.all import sniff, wrpcap, DNSQR, DNSRR, TCP, IP, Raw
from datetime import datetime

pcap_packets = []

# Config
FILTER_PORTS = [53, 80, 443]
MAX_PACKETS = 100  # to modify
EXPORT_PATH = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

def is_http(packet):
    return packet.haslayer(Raw) and b"HTTP" in packet[Raw].load

def handle_packet(packet):
    if IP in packet:
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer("UDP") else "OTHER"
        src = packet[IP].src
        dst = packet[IP].dst

        # Port filtering
        sport = packet.sport if hasattr(packet, 'sport') else None
        dport = packet.dport if hasattr(packet, 'dport') else None
        if sport not in FILTER_PORTS and dport not in FILTER_PORTS:
            return

        # DNS
        if packet.haslayer(DNSQR):
            print(f"[DNS][REQ] {src} -> {dst} | {packet[DNSQR].qname.decode()}")
        elif packet.haslayer(DNSRR):
            print(f"[DNS][RESP] {src} -> {dst} | {packet[DNSRR].rrname.decode()} -> {packet[DNSRR].rdata}")

        # HTTP
        elif is_http(packet):
            try:
                http_payload = packet[Raw].load.decode(errors='ignore')
                lines = http_payload.split('\r\n')
                request_line = lines[0]
                print(f"[HTTP] {src} -> {dst} | {request_line}")
            except Exception as e:
                pass

        # Backup for .pcap
        pcap_packets.append(packet)

print("Active sniff ... Press CTRL+C to stop.")
try:
    sniff(prn=handle_packet, count=MAX_PACKETS, store=False)
except KeyboardInterrupt:
    print("\nInterrupted capture.")

# Export .pcap
if pcap_packets:
    wrpcap(EXPORT_PATH, pcap_packets)
    print(f"[✔] Exported to : {EXPORT_PATH}")
else:
    print("[!] No saving package.")
