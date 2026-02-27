# 🕵️ packet-sniffer

> A lightweight **network packet sniffer** built in Python using [Scapy](https://scapy.net/) — captures and inspects live network traffic at the packet level for educational and security research purposes.

---

## ⚠️ Legal Disclaimer

> This tool is intended **for educational and authorized security research purposes only**. Only use it on networks you own or have explicit permission to monitor. Unauthorized packet sniffing is illegal in most jurisdictions.

---

## 📋 Description

**packet-sniffer** is a Python-based network analysis tool that leverages the power of the **Scapy** library to capture, parse, and display live network packets. The project includes two sniffer variants (`sniffer1.py` and `sniffer2.py`) that demonstrate different levels of packet inspection and filtering.

Whether you're learning about network protocols, debugging traffic, or studying cybersecurity, this project gives you a hands-on look at how data flows through a network interface.

---

## 🗂️ Project Structure

```
packet-sniffer/
├── sniffer1.py      # Basic packet sniffer — captures and displays raw packets
├── sniffer2.py      # Advanced sniffer — filtered capture with protocol analysis
└── README.md
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3 |
| Packet Library | [Scapy](https://scapy.net/) |
| Environment | Python virtual environment (`venv`) |
| Protocols | Ethernet, IP, TCP, UDP, ICMP, and more |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.x
- Root / Administrator privileges (required for raw socket access)
- Linux or macOS recommended (Scapy works on Windows with Npcap)

---

### 1. Clone the repository

```bash
git clone https://github.com/yannisduvignau/packet-sniffer.git
cd packet-sniffer
```

### 2. Create a Python virtual environment

```bash
python3 -m venv env
```

### 3. Activate the virtual environment

```bash
# macOS / Linux
source env/bin/activate

# Windows
env\Scripts\activate
```

### 4. Install dependencies

```bash
echo "scapy" > requirements.txt
pip install -r requirements.txt
```

### 5. Run the sniffer

```bash
# Run the basic sniffer
sudo python3 sniffer1.py

# Run the advanced sniffer
sudo python3 sniffer2.py
```

> **Note:** `sudo` is required because capturing raw network packets requires root privileges.

### 6. Deactivate the virtual environment

```bash
deactivate
```

---

## 🔍 Sniffer Variants

### `sniffer1.py` — Basic Sniffer
Captures all packets on the default network interface and prints a summary for each one. Great for getting a real-time overview of all network activity.

**Features:**
- Captures packets on all protocols
- Displays source/destination IP addresses and ports
- Shows protocol type (TCP, UDP, ICMP…)

### `sniffer2.py` — Advanced Sniffer
A more refined sniffer with filtering capabilities and deeper protocol dissection. Allows targeting specific traffic types.

**Features:**
- BPF (Berkeley Packet Filter) filter support (e.g., only capture HTTP or DNS traffic)
- Layer-by-layer packet dissection (Ethernet → IP → TCP/UDP → Payload)
- Optional packet count limit

---

## 🌐 Protocols Supported

| Layer | Protocols |
|-------|----------|
| Layer 2 (Data Link) | Ethernet, ARP |
| Layer 3 (Network) | IP, ICMP, IPv6 |
| Layer 4 (Transport) | TCP, UDP |
| Layer 7 (Application) | HTTP, DNS, FTP *(via payload inspection)* |

---

## 💡 Usage Examples

```bash
# Capture all traffic (default interface)
sudo python3 sniffer1.py

# Capture only TCP packets (if BPF filter is implemented in sniffer2)
sudo python3 sniffer2.py --filter "tcp"

# Capture DNS traffic only
sudo python3 sniffer2.py --filter "udp port 53"

# Capture HTTP traffic
sudo python3 sniffer2.py --filter "tcp port 80"
```

---

## 🧠 Concepts Covered

| Topic | Description |
|-------|-------------|
| Raw Sockets | Capturing packets below the application layer |
| Scapy API | `sniff()`, `PacketList`, layer dissection |
| BPF Filters | Berkeley Packet Filter syntax for targeted captures |
| Protocol Stack | Understanding OSI model layers in practice |
| Network Forensics | Inspecting packet payloads and headers |

---

## 📁 Generated Files

The following files are excluded from version control via `.gitignore`:

```
env/               # Virtual environment
requirements.txt   # Dependencies
.env*              # Environment variables
*.log              # Log files
*.pcap             # Captured packet files
```

> `.pcap` files can be opened with [Wireshark](https://www.wireshark.org/) for further analysis.

---

## 🔒 Security & Ethical Use

- **Only sniff traffic on networks you own or are authorized to monitor**
- Do not capture credentials, personal data, or private communications
- Use in a controlled lab environment (e.g., isolated VM, local network)
- Pair with [Wireshark](https://www.wireshark.org/) for deeper GUI-based analysis

---

## 🤝 Contributing

1. Fork the project
2. Create your branch (`git checkout -b feature/new-filter`)
3. Commit your changes (`git commit -m 'Add DNS filter support'`)
4. Push to the branch (`git push origin feature/new-filter`)
5. Open a Pull Request

---

## 👤 Author

**Yannis Duvignau**  
[GitHub](https://github.com/yannisduvignau)

---

## 📚 Resources

- 📖 [Scapy Documentation](https://scapy.readthedocs.io/)
- 🦈 [Wireshark](https://www.wireshark.org/) — GUI packet analyzer
- 📡 [BPF Filter Syntax](https://biot.com/capstats/bpf.html)
- 🔐 [tcpdump man page](https://www.tcpdump.org/manpages/tcpdump.1.html)

---

## 📄 License

This project is distributed under an open license. See the `LICENSE` file for more details.