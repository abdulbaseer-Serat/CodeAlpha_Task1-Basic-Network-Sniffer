import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.utils import wrpcap
import threading

# Store packets
packets = []
sniffing = False

# Process packets
def process_packet(packet):
    if packet.haslayer(IP):
        ip = packet[IP]

        protocol = "Other"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        info = f"{ip.src} → {ip.dst} ({protocol})"

        packets.append(packet)

        tree.insert("", "end",
                    values=(ip.src, ip.dst, protocol, info))

        counter_label.config(text=f"Packets: {len(packets)}")


# Sniff packets (controlled)
def sniff_packets():
    global sniffing
    sniffing = True

    sniff(
        prn=process_packet,
        store=False,
        iface="Wi-Fi",  # ✅ CHANGE if needed (Ethernet if cable)
        stop_filter=lambda x: not sniffing
    )


# Start capture
def start_capture():
    thread = threading.Thread(target=sniff_packets)
    thread.daemon = True
    thread.start()


# Stop capture
def stop_capture():
    global sniffing
    sniffing = False


# Save packets
def save_packets():
    if not packets:
        print("No packets to save")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".pcap",
        filetypes=[("PCAP files", "*.pcap")]
    )

    if file_path:
        wrpcap(file_path, packets)
        print(f"Saved to {file_path}")


# Show packet details
def show_packet(event):
    selected = tree.focus()
    if not selected:
        return

    index = tree.index(selected)
    if index < len(packets):
        pkt = packets[index]
        details.delete("1.0", tk.END)
        details.insert(tk.END, pkt.show(dump=True))


# GUI Setup
root = tk.Tk()
root.title("Mini Wireshark")
root.geometry("1000x600")

# Table
columns = ("Source IP", "Destination IP", "Protocol", "Info")
tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=200)

tree.pack(fill=tk.BOTH, expand=True)

# Packet details
details = tk.Text(root, height=15)
details.pack(fill=tk.BOTH, expand=True)

# Buttons
btn_frame = tk.Frame(root)
btn_frame.pack()

start_btn = tk.Button(btn_frame, text="Start Capture", command=start_capture)
start_btn.pack(side=tk.LEFT, padx=5)

stop_btn = tk.Button(btn_frame, text="Stop Capture", command=stop_capture)
stop_btn.pack(side=tk.LEFT, padx=5)

save_btn = tk.Button(btn_frame, text="Save Packets", command=save_packets)
save_btn.pack(side=tk.LEFT, padx=5)

# Packet counter
counter_label = tk.Label(root, text="Packets: 0")
counter_label.pack()

# Click event
tree.bind("<<TreeviewSelect>>", show_packet)

root.mainloop()