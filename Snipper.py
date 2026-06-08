from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR

def process_packet(packet):
    print("\n============================")

    # ✅ IP Layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")

    # ✅ Protocol Detection
    if packet.haslayer(TCP):
        print("Protocol       : TCP")
    elif packet.haslayer(UDP):
        print("Protocol       : UDP")
    elif packet.haslayer(ICMP):
        print("Protocol       : ICMP")
    else:
        print("Protocol       : Other")

    # ✅ Website Detection (DNS)
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        website = packet[DNSQR].qname.decode()
        print(f"Website        : {website}")

    # ✅ Payload (data)
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        print(f"Payload        : {payload[:50]}")  # limit size


print("Starting Network Sniffer... Press Ctrl+C to stop")

sniff(
    prn=process_packet,
    store=False,
    iface="Wi-Fi"   # ✅ Change if needed (Ethernet)
)
