from flask import Flask, render_template, jsonify
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP
import socket
import threading

app = Flask(__name__)

packets = []
lock = threading.Lock()

sniffer = None
capture_running = False


# ✅ Packet handler
def packet_callback(packet):
    global packets

    if not packet.haslayer(IP):
        return

    protocol = "UNKNOWN"

    # ✅ Detect protocol by number
    proto_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }

    proto_num = packet[IP].proto
    protocol = proto_map.get(proto_num, f"OTHER({proto_num})")

    # ✅ Improve protocol detection
    if packet.haslayer(DNS):
        protocol = "DNS"
    elif packet.haslayer(TCP):
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            protocol = "HTTP"
        elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
            protocol = "HTTPS"
        elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
            protocol = "FTP"
        elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
            protocol = "SSH"
        elif packet[TCP].dport == 25 or packet[TCP].sport == 25:
            protocol = "SMTP"
    elif packet.haslayer(UDP):
        if packet[UDP].dport == 53:
            protocol = "DNS"

    # ✅ Safe domain lookup
    try:
        domain = socket.gethostbyaddr(packet[IP].dst)[0]
    except:
        domain = "Unknown"

    # ✅ Ports
    src_port = packet.sport if hasattr(packet, 'sport') else ""
    dst_port = packet.dport if hasattr(packet, 'dport') else ""

    data = {
        "source": packet[IP].src,
        "destination": packet[IP].dst,
        "domain": domain,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port
    }

    with lock:
        packets.append(data)
        if len(packets) > 100:
            packets.pop(0)


# ✅ Start capture
@app.route("/start")
def start_capture():
    global sniffer, capture_running

    if not capture_running:
        capture_running = True
        sniffer = AsyncSniffer(prn=packet_callback, store=False)
        sniffer.start()

    return jsonify({"status": "started"})


# ✅ Stop capture
@app.route("/stop")
def stop_capture():
    global sniffer, capture_running

    capture_running = False

    if sniffer:
        sniffer.stop()
        sniffer = None

    return jsonify({"status": "stopped"})


# ✅ Get packets
@app.route("/packets")
def get_packets():
    with lock:
        return jsonify(list(packets))


# ✅ GUI
@app.route("/")
def home():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True, threaded=True)