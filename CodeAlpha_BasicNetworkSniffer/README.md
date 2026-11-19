# CodeAlpha – Basic Network Sniffer

> **CodeAlpha Cyber Security Internship – Task 1**
> A Python packet sniffer that captures live network traffic and decodes every packet layer by layer, so you can *see* how data flows through a network.

![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey) ![Tests](https://img.shields.io/badge/tests-11%20passing-brightgreen)

---

## Features

| Feature | Details |
|---|---|
| **Two capture back-ends** | `scapy` (cross-platform, BPF filters) or a zero-dependency raw `socket` (Linux `AF_PACKET`) |
| **Hand-written dissector** | Every header is unpacked with `struct`: Ethernet, 802.1Q VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6 |
| **Application layer** | DNS queries & answers (with name compression), HTTP request/response lines + `Host`, TLS record types + **SNI** from ClientHello |
| **Useful display** | Source/destination IP & port, protocol, TCP flags, seq/ack, TTL, service names (HTTP, SSH, DNS …) |
| **Payload inspection** | Hex + ASCII dump of the first *N* payload bytes (`--payload N`) |
| **Verbose mode** | `-v` prints every decoded field of every layer |
| **Filters** | Display filters `-p/--host/--port`, kernel BPF filter `-f` (scapy) |
| **PCAP export** | `-w file.pcap` – open it in Wireshark |
| **Statistics** | Protocol distribution, top talkers, top conversations at the end |
| **Robust** | Truncated / malformed packets never crash the program (unit-tested) |

## Project structure

```
CodeAlpha_BasicNetworkSniffer/
├── sniffer.py              # the sniffer (single file, ~550 lines, commented)
├── tests/test_dissector.py # 11 unit tests with hand-crafted packets (no root needed)
├── docs/sample_output.txt  # real capture: TCP handshake, HTTP, DNS, ICMP
├── requirements.txt        # scapy (optional)
└── README.md
```

## Installation

```bash
git clone https://github.com/Djaneba/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer
pip install -r requirements.txt     # optional on Linux, required on Windows/macOS
```

* **Linux** – works out of the box with the built-in `socket` back-end (no install).
* **Windows** – install [Npcap](https://npcap.com/) (tick *“WinPcap API-compatible mode”*) + `pip install scapy`, then run the terminal **as Administrator**.
* **macOS** – `pip install scapy`, run with `sudo`.

## Usage

```bash
sudo python3 sniffer.py                          # capture until Ctrl+C
sudo python3 sniffer.py -c 30                    # stop after 30 packets
sudo python3 sniffer.py -i eth0 -p dns -v        # only DNS, all header fields
sudo python3 sniffer.py --host 192.168.1.10      # traffic to/from one host
sudo python3 sniffer.py -f "tcp port 80" --payload 128   # BPF + payload hexdump
sudo python3 sniffer.py -t 60 -w traffic.pcap    # 60 s capture saved for Wireshark
python3 sniffer.py -h                            # all options
```

| Option | Description |
|---|---|
| `-i, --iface` | interface to listen on (`eth0`, `wlan0`, `lo`, `Wi-Fi` …) |
| `-c, --count` | number of packets (0 = unlimited) |
| `-t, --timeout` | stop after N seconds |
| `-p, --protocol` | `tcp`, `udp`, `icmp`, `arp`, `dns`, `http`, `tls`, `ipv6` … |
| `--host`, `--port` | only packets involving this IP / port |
| `-f, --bpf` | kernel BPF filter (scapy back-end) |
| `--payload N` | hexdump first N bytes of payload |
| `-v, --verbose` | print every decoded header field |
| `-w, --write` | save matching packets to a `.pcap` file |
| `--backend` | `auto` (default), `scapy`, `socket` |

## Sample output

Capturing a `curl http://127.0.0.1:8099/` and a DNS query (full output in [`docs/sample_output.txt`](docs/sample_output.txt)):

```
No.          Time  Proto                     Source    Destination                 Len  Info
--------------------------------------------------------------------------------------------------------------
#1        0.9522s  TCP              127.0.0.1:37076 -> 127.0.0.1:8099              74B  [SYN] seq=3408933828 ack=0 win=65495 len=0
#2        0.9524s  TCP               127.0.0.1:8099 -> 127.0.0.1:37076             74B  [SYN,ACK] seq=683410949 ack=3408933829 ...
#3        0.9525s  TCP              127.0.0.1:37076 -> 127.0.0.1:8099              66B  [ACK] seq=3408933829 ack=683410950 ...
#4        0.9525s  HTTP             127.0.0.1:37076 -> 127.0.0.1:8099             143B  GET / HTTP/1.1  [Host: 127.0.0.1:8099]
      Ethernet  src=00:00:00:00:00:00  dst=00:00:00:00:00:00  type=IPv4
      IPv4      version=4  header_len=20  tos=0  total_len=129  id=...  flags=DF  ttl=64  protocol=TCP ...
      TCP       src_port=37076  dst_port=8099  seq=3408933829  ack=683410950  header_len=32  flags=PSH,ACK ...
      HTTP      start-line=GET / HTTP/1.1  host=127.0.0.1:8099
      Payload (77 bytes, truncated):
      0000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..
...
#6        0.9538s  HTTP              127.0.0.1:8099 -> 127.0.0.1:37076            222B  HTTP/1.0 200 OK
#10       0.9542s  TCP               127.0.0.1:8099 -> 127.0.0.1:37076             66B  [FIN,ACK] ...
#13       0.9720s  DNS              127.0.0.1:60389 -> 127.0.0.1:53                74B  DNS query codealpha.tech A
#14       0.9721s  ICMP                   127.0.0.1 -> 127.0.0.1                  102B  Destination Unreachable (code 3)

  Protocol distribution
    TCP            10   71.4%  ###################################
    HTTP            2   14.3%  #######
    DNS             1    7.1%  ###
    ICMP            1    7.1%  ###
```

## What I learned – how data flows through a network

Every packet is a set of **nested envelopes** (the TCP/IP model). The sniffer opens them one by one:

```
+----------------+-------------+-------------+-------------------------+
| Ethernet (14B) | IPv4 (20B+) | TCP (20B+)  | Payload (HTTP, TLS ...) |
|  MAC src/dst   |  IP src/dst |  ports,     |  the application data   |
|  EtherType     |  TTL, proto |  seq/ack,   |                         |
|                |             |  flags      |                         |
+----------------+-------------+-------------+-------------------------+
   Link layer      Network        Transport       Application
```

1. **Ethernet** – delivers the frame to the next device on the local network (MAC addresses). The *EtherType* field (`0x0800` IPv4, `0x86DD` IPv6, `0x0806` ARP) tells us what is inside.
2. **IP** – routes the packet end-to-end across networks. *TTL* decreases at each router; *protocol* (6 = TCP, 17 = UDP, 1 = ICMP) says what comes next.
3. **TCP / UDP** – ports identify the application (80 HTTP, 443 HTTPS, 53 DNS). TCP is reliable: the capture above shows the **3-way handshake** (`SYN → SYN,ACK → ACK`), data with `PSH,ACK`, and the **graceful close** (`FIN,ACK`). UDP (DNS) just sends a datagram.
4. **Application** – HTTP is plain text, so anyone on the path can read it (URLs, headers, even passwords). HTTPS/TLS encrypts the payload, but the **SNI** in the ClientHello still reveals which website is being visited.
5. **ARP** – resolves IP → MAC on the LAN (`Who has 192.168.1.1? Tell 192.168.1.10`), which is also why ARP spoofing attacks are possible.

**Security takeaways:** unencrypted protocols (HTTP, FTP, Telnet, plain DNS) leak data to anyone sniffing the network → always prefer TLS, SSH, DoH/DoT; use switched networks, WPA3 and network segmentation; monitor for unexpected ARP replies.

## Running the tests

```bash
python3 -m unittest discover -s tests -v     # no root required
```

The tests build Ethernet/IP/TCP/UDP/DNS/ARP/TLS packets byte by byte and check the dissector output, filters, the PCAP writer, and that truncated packets never crash it.

## Ethics & legal notice

Packet sniffing can capture private data. Only run this tool on networks **you own** or where you have **explicit written permission**. This project was built for educational purposes during the CodeAlpha internship.

## Author

**Amadou Sanoko Djaneba** – Cyber Security Intern @ CodeAlpha
[GitHub](https://github.com/Djaneba)
