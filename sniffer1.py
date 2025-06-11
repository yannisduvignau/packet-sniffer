from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = ip_layer.proto
        src = ip_layer.src
        dst = ip_layer.dst

        print(f"[IP] {src} -> {dst} | Protocol: {proto}", end="")

        if TCP in packet:
            print(" | TCP Packet")
        elif UDP in packet:
            print(" | UDP Packet")
        elif ICMP in packet:
            print(" | ICMP Packet")
        else:
            print(" | Other IP Packet")

def main():
    print("Sniffer Scapy démarré... (Ctrl+C pour arrêter)")
    # Promisescuous mode activated, without filtering (default interface)
    sniff(filter="ip", prn=packet_callback, store=0)
    # sniff(filter="ip", prn=packet_callback, store=0, iface="en0")

if __name__ == '__main__':
    main()