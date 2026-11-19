#!/usr/bin/env python3
"""
CodeAlpha - Task 1: Basic Network Sniffer
=========================================

A command-line packet sniffer that captures live network traffic and decodes
it layer by layer (Ethernet -> ARP / IPv4 / IPv6 -> TCP / UDP / ICMP -> DNS /
HTTP / TLS) so you can see how data actually flows through a network.

Two capture back-ends are supported:

* scapy  - cross-platform (Linux, macOS, Windows + Npcap), supports BPF filters
* socket - zero-dependency raw socket (AF_PACKET), Linux only

Both back-ends hand raw frames to the same hand-written dissector, which is
the educational core of the project: every header field is unpacked with
`struct` so the packet structure is fully visible in the code.

Usage examples (run as root / Administrator):
    sudo python3 sniffer.py                         # capture forever
    sudo python3 sniffer.py -c 50 -p tcp            # 50 TCP packets
    sudo python3 sniffer.py -i eth0 -f "port 53"    # BPF filter (scapy)
    sudo python3 sniffer.py -c 100 -w capture.pcap  # save for Wireshark
    sudo python3 sniffer.py --payload 64 -v         # show payload hexdump

Legal note: only sniff networks you own or are explicitly authorised to test.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #
ETH_P_ALL = 0x0003
ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q"}
IP_PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 47: "GRE", 50: "ESP"}
WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NETBIOS",
    143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1900: "SSDP", 3306: "MYSQL", 3389: "RDP", 5353: "mDNS",
    8080: "HTTP-ALT",
}
ICMP_TYPES = {0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
              8: "Echo Request", 11: "Time Exceeded"}
DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
              16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
             (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ",
                b"PATCH ", b"HTTP/1.")


# --------------------------------------------------------------------------- #
#  Terminal colours
# --------------------------------------------------------------------------- #
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; GREY = "\033[90m"

    @classmethod
    def disable(cls) -> None:
        for name in list(vars(cls)):
            if name.isupper():
                setattr(cls, name, "")


PROTO_COLOURS = {"TCP": "GREEN", "UDP": "BLUE", "ICMP": "YELLOW", "ICMPv6": "YELLOW",
                 "ARP": "MAGENTA", "DNS": "CYAN", "HTTP": "RED", "TLS": "GREEN"}


# --------------------------------------------------------------------------- #
#  Parsed packet model
# --------------------------------------------------------------------------- #
@dataclass
class Packet:
    number: int
    timestamp: float
    length: int
    src_mac: str = ""
    dst_mac: str = ""
    ethertype: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    ttl: Optional[int] = None
    protocol: str = "OTHER"          # highest identified protocol
    transport: str = ""              # TCP / UDP / ICMP ...
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    info: str = ""
    payload: bytes = b""
    layers: list = field(default_factory=list)   # [(layer name, {field: value})]


# --------------------------------------------------------------------------- #
#  Dissector: raw bytes -> Packet
# --------------------------------------------------------------------------- #
def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def tcp_flags_str(flags: int) -> str:
    return ",".join(name for bit, name in TCP_FLAGS if flags & bit) or "-"


def service(port: Optional[int]) -> str:
    return WELL_KNOWN_PORTS.get(port, "") if port is not None else ""


def parse_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels, jumped, next_off = [], False, offset
    while offset < len(data) and depth < 20:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:                      # compression pointer
            if offset + 1 >= len(data):
                break
            ptr = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                next_off = offset + 2
            name, _ = parse_dns_name(data, ptr, depth + 1)
            labels.append(name)
            jumped = True
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(l for l in labels if l), (next_off if jumped else offset)


def dissect_dns(pkt: Packet, data: bytes) -> None:
    if len(data) < 12:
        return
    tid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    is_response = bool(flags & 0x8000)
    fields = {"id": hex(tid), "qr": "response" if is_response else "query",
              "questions": qd, "answers": an}
    try:
        name, off = parse_dns_name(data, 12)
        qtype = struct.unpack("!H", data[off:off + 2])[0] if off + 2 <= len(data) else 0
        qname = DNS_QTYPES.get(qtype, str(qtype))
        fields["query"] = f"{name} ({qname})"
        answers = []
        off += 4
        for _ in range(min(an, 10)):
            _, off = parse_dns_name(data, off)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            if rtype == 1 and rdlen == 4:
                answers.append(socket.inet_ntoa(rdata))
            elif rtype == 28 and rdlen == 16:
                answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype == 5:
                answers.append("CNAME " + parse_dns_name(data, off)[0])
            off += rdlen
        if answers:
            fields["answers_data"] = ", ".join(answers)
        pkt.info = (f"DNS {'response' if is_response else 'query'} {name} {qname}"
                    + (f" -> {', '.join(answers)}" if answers else ""))
    except (struct.error, IndexError, ValueError, OSError):
        pkt.info = "DNS (malformed)"
    pkt.protocol = "DNS"
    pkt.layers.append(("DNS", fields))


def dissect_application(pkt: Packet, payload: bytes) -> None:
    """Very light application-layer identification."""
    ports = {pkt.src_port, pkt.dst_port}
    if (53 in ports or 5353 in ports) and payload:
        if pkt.transport == "TCP" and len(payload) > 2:   # TCP DNS has 2-byte length
            payload = payload[2:]
        dissect_dns(pkt, payload)
        return
    if payload.startswith(HTTP_METHODS):
        first_line = payload.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        host = ""
        for line in payload.split(b"\r\n")[1:]:
            if line.lower().startswith(b"host:"):
                host = line[5:].strip().decode("latin-1", "replace")
                break
        pkt.protocol = "HTTP"
        pkt.info = first_line + (f"  [Host: {host}]" if host else "")
        pkt.layers.append(("HTTP", {"start-line": first_line, "host": host or "-"}))
        return
    if len(payload) >= 6 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
        content = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake",
                   0x17: "Application Data"}[payload[0]]
        detail = ""
        if payload[0] == 0x16 and payload[5] == 0x01:
            detail = " ClientHello"
            sni = extract_sni(payload)
            if sni:
                detail += f" SNI={sni}"
        elif payload[0] == 0x16 and payload[5] == 0x02:
            detail = " ServerHello"
        pkt.protocol = "TLS"
        pkt.info = f"TLS {content}{detail}"
        pkt.layers.append(("TLS", {"content-type": content,
                                   "version": f"0x{payload[1]:02x}{payload[2]:02x}"}))


def extract_sni(record: bytes) -> str:
    """Pull the Server Name Indication out of a TLS ClientHello (best effort)."""
    try:
        p = 5 + 4 + 2 + 32                       # record hdr, hs hdr, version, random
        p += 1 + record[p]                       # session id
        p += 2 + struct.unpack("!H", record[p:p + 2])[0]   # cipher suites
        p += 1 + record[p]                       # compression methods
        end = p + 2 + struct.unpack("!H", record[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", record[p:p + 4])
            p += 4
            if etype == 0:                       # server_name
                nlen = struct.unpack("!H", record[p + 3:p + 5])[0]
                return record[p + 5:p + 5 + nlen].decode("ascii", "replace")
            p += elen
    except (IndexError, struct.error):
        pass
    return ""


def dissect_transport(pkt: Packet, proto: int, data: bytes) -> None:
    name = IP_PROTOCOLS.get(proto, f"IP-proto-{proto}")
    pkt.transport = pkt.protocol = name

    if proto == 6 and len(data) >= 20:                                   # TCP
        sport, dport, seq, ack, off_flags, win = struct.unpack("!HHIIHH", data[:16])
        hdr_len = (off_flags >> 12) * 4
        flags = off_flags & 0x01FF
        pkt.src_port, pkt.dst_port = sport, dport
        pkt.payload = data[hdr_len:]
        pkt.layers.append(("TCP", {"src_port": sport, "dst_port": dport, "seq": seq,
                                   "ack": ack, "header_len": hdr_len,
                                   "flags": tcp_flags_str(flags), "window": win}))
        pkt.info = (f"[{tcp_flags_str(flags)}] seq={seq} ack={ack} win={win} "
                    f"len={len(pkt.payload)}")
    elif proto == 17 and len(data) >= 8:                                 # UDP
        sport, dport, ulen, _csum = struct.unpack("!HHHH", data[:8])
        pkt.src_port, pkt.dst_port = sport, dport
        pkt.payload = data[8:]
        pkt.layers.append(("UDP", {"src_port": sport, "dst_port": dport, "length": ulen}))
        pkt.info = f"len={len(pkt.payload)}"
    elif proto in (1, 58) and len(data) >= 4:                            # ICMP / v6
        itype, code = data[0], data[1]
        desc = ICMP_TYPES.get(itype, f"type {itype}") if proto == 1 else f"type {itype}"
        if proto == 58:
            desc = {128: "Echo Request", 129: "Echo Reply", 133: "Router Solicitation",
                    134: "Router Advertisement", 135: "Neighbor Solicitation",
                    136: "Neighbor Advertisement"}.get(itype, desc)
        pkt.payload = data[8:]
        pkt.layers.append((name, {"type": itype, "code": code, "description": desc}))
        pkt.info = f"{desc} (code {code})"
        return
    else:
        pkt.payload = data
        return

    svc = service(pkt.dst_port) or service(pkt.src_port)
    if svc:
        pkt.info = f"{svc}  " + pkt.info
    if pkt.payload:
        dissect_application(pkt, pkt.payload)


def dissect_ipv4(pkt: Packet, data: bytes) -> None:
    if len(data) < 20:
        return
    ver_ihl, tos, total_len, ident, frag, ttl, proto, csum, src, dst = \
        struct.unpack("!BBHHHBBH4s4s", data[:20])
    ihl = (ver_ihl & 0x0F) * 4
    pkt.src_ip, pkt.dst_ip, pkt.ttl = socket.inet_ntoa(src), socket.inet_ntoa(dst), ttl
    pkt.layers.append(("IPv4", {"version": ver_ihl >> 4, "header_len": ihl, "tos": tos,
                                "total_len": total_len, "id": ident,
                                "flags": ("DF " if frag & 0x4000 else "") + ("MF" if frag & 0x2000 else ""),
                                "ttl": ttl, "protocol": IP_PROTOCOLS.get(proto, proto),
                                "checksum": hex(csum), "src": pkt.src_ip, "dst": pkt.dst_ip}))
    dissect_transport(pkt, proto, data[ihl:total_len] if total_len else data[ihl:])


def dissect_ipv6(pkt: Packet, data: bytes) -> None:
    if len(data) < 40:
        return
    vtf, plen, nxt, hlim = struct.unpack("!IHBB", data[:8])
    pkt.src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    pkt.dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
    pkt.ttl = hlim
    pkt.layers.append(("IPv6", {"version": vtf >> 28, "payload_len": plen,
                                "next_header": IP_PROTOCOLS.get(nxt, nxt), "hop_limit": hlim,
                                "src": pkt.src_ip, "dst": pkt.dst_ip}))
    dissect_transport(pkt, nxt, data[40:40 + plen])


def dissect_arp(pkt: Packet, data: bytes) -> None:
    if len(data) < 28:
        return
    _htype, _ptype, _hlen, _plen, op = struct.unpack("!HHBBH", data[:8])
    sha, spa, tha, tpa = data[8:14], data[14:18], data[18:24], data[24:28]
    pkt.protocol = pkt.transport = "ARP"
    pkt.src_ip, pkt.dst_ip = socket.inet_ntoa(spa), socket.inet_ntoa(tpa)
    if op == 1:
        pkt.info = f"Who has {pkt.dst_ip}? Tell {pkt.src_ip}"
    elif op == 2:
        pkt.info = f"{pkt.src_ip} is at {mac_str(sha)}"
    else:
        pkt.info = f"ARP op {op}"
    pkt.layers.append(("ARP", {"operation": {1: "request", 2: "reply"}.get(op, op),
                               "sender_mac": mac_str(sha), "sender_ip": pkt.src_ip,
                               "target_mac": mac_str(tha), "target_ip": pkt.dst_ip}))


def dissect(raw: bytes, number: int, ts: float) -> Packet:
    """Entry point: decode an Ethernet frame."""
    pkt = Packet(number=number, timestamp=ts, length=len(raw))
    if len(raw) < 14:
        return pkt
    dst, src, etype = struct.unpack("!6s6sH", raw[:14])
    offset = 14
    if etype == 0x8100 and len(raw) >= 18:                 # VLAN tag
        etype = struct.unpack("!H", raw[16:18])[0]
        offset = 18
    pkt.dst_mac, pkt.src_mac = mac_str(dst), mac_str(src)
    pkt.ethertype = ETHERTYPES.get(etype, hex(etype))
    pkt.layers.append(("Ethernet", {"src": pkt.src_mac, "dst": pkt.dst_mac,
                                    "type": pkt.ethertype}))
    body = raw[offset:]
    try:
        if etype == 0x0800:
            dissect_ipv4(pkt, body)
        elif etype == 0x86DD:
            dissect_ipv6(pkt, body)
        elif etype == 0x0806:
            dissect_arp(pkt, body)
        else:
            pkt.protocol = pkt.ethertype
    except (struct.error, IndexError, ValueError, OSError) as exc:
        pkt.info = f"(dissector error: {exc})"
    return pkt


# --------------------------------------------------------------------------- #
#  Output helpers
# --------------------------------------------------------------------------- #
def hexdump(data: bytes, width: int = 16, indent: str = "      ") -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{C.GREY}{i:04x}{C.RESET}  {hexpart:<{width * 3}} {C.DIM}{asc}{C.RESET}")
    return "\n".join(lines)


def endpoint(ip: str, port: Optional[int]) -> str:
    if not ip:
        return "?"
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def print_packet(pkt: Packet, start: float, payload_bytes: int, verbose: bool) -> None:
    colour = getattr(C, PROTO_COLOURS.get(pkt.protocol, "RESET"), "")
    rel = pkt.timestamp - start
    src = endpoint(pkt.src_ip, pkt.src_port) if pkt.src_ip else pkt.src_mac
    dst = endpoint(pkt.dst_ip, pkt.dst_port) if pkt.dst_ip else pkt.dst_mac
    print(f"{C.GREY}#{pkt.number:<5}{C.RESET} {rel:9.4f}s  "
          f"{colour}{C.BOLD}{pkt.protocol:<7}{C.RESET} "
          f"{src:>24} {C.GREY}->{C.RESET} {dst:<24} "
          f"{C.GREY}{pkt.length:>5}B{C.RESET}  {pkt.info}")
    if verbose:
        for name, fields in pkt.layers:
            items = "  ".join(f"{k}={v}" for k, v in fields.items())
            print(f"      {C.CYAN}{name:<9}{C.RESET} {C.DIM}{items}{C.RESET}")
    if payload_bytes and pkt.payload:
        shown = pkt.payload[:payload_bytes]
        print(f"      {C.YELLOW}Payload{C.RESET} ({len(pkt.payload)} bytes"
              f"{', truncated' if len(pkt.payload) > payload_bytes else ''}):")
        print(hexdump(shown))


class Stats:
    def __init__(self) -> None:
        self.protocols: Counter = Counter()
        self.talkers: Counter = Counter()
        self.conversations: Counter = Counter()
        self.total_bytes = 0
        self.count = 0
        self.start = time.time()

    def add(self, pkt: Packet) -> None:
        self.count += 1
        self.total_bytes += pkt.length
        self.protocols[pkt.protocol] += 1
        if pkt.src_ip:
            self.talkers[pkt.src_ip] += pkt.length
            self.conversations[(pkt.src_ip, pkt.dst_ip, pkt.transport)] += 1

    def report(self) -> None:
        dur = max(time.time() - self.start, 1e-6)
        bar = "=" * 72
        print(f"\n{C.BOLD}{bar}\n  CAPTURE SUMMARY\n{bar}{C.RESET}")
        print(f"  Packets captured : {self.count}")
        print(f"  Bytes captured   : {self.total_bytes:,}")
        print(f"  Duration         : {dur:.2f}s  ({self.count / dur:.1f} pkt/s)")
        if self.protocols:
            print(f"\n  {C.BOLD}Protocol distribution{C.RESET}")
            for proto, n in self.protocols.most_common():
                pct = 100 * n / self.count
                print(f"    {proto:<10} {n:>6}  {pct:5.1f}%  {'#' * int(pct / 2)}")
        if self.talkers:
            print(f"\n  {C.BOLD}Top talkers (bytes sent){C.RESET}")
            for ip, b in self.talkers.most_common(5):
                print(f"    {ip:<40} {b:>10,} B")
        if self.conversations:
            print(f"\n  {C.BOLD}Top conversations{C.RESET}")
            for (s, d, t), n in self.conversations.most_common(5):
                print(f"    {s} -> {d} [{t}]  {n} pkts")
        print(bar)


# --------------------------------------------------------------------------- #
#  PCAP writer (works with any back-end; open the file in Wireshark)
# --------------------------------------------------------------------------- #
class PcapWriter:
    def __init__(self, path: str, linktype: int = 1) -> None:
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))

    def write(self, raw: bytes, ts: float) -> None:
        sec, usec = int(ts), int((ts - int(ts)) * 1_000_000)
        self.fh.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
        self.fh.write(raw)

    def close(self) -> None:
        self.fh.close()


# --------------------------------------------------------------------------- #
#  Filters
# --------------------------------------------------------------------------- #
def matches(pkt: Packet, proto: Optional[str], host: Optional[str], port: Optional[int]) -> bool:
    if proto:
        p = proto.upper()
        if p not in (pkt.protocol.upper(), pkt.transport.upper(), pkt.ethertype.upper()):
            return False
    if host and host not in (pkt.src_ip, pkt.dst_ip):
        return False
    if port is not None and port not in (pkt.src_port, pkt.dst_port):
        return False
    return True


# --------------------------------------------------------------------------- #
#  Capture back-ends
# --------------------------------------------------------------------------- #
def capture_socket(iface: Optional[str], handler, count: int, timeout: Optional[float]) -> None:
    """Linux raw socket capture (no third-party dependency)."""
    if not hasattr(socket, "AF_PACKET"):
        sys.exit("[!] The 'socket' back-end needs Linux (AF_PACKET). "
                 "Install scapy (+ Npcap on Windows) and use --backend scapy.")
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    if iface:
        sock.bind((iface, 0))
    sock.settimeout(1.0)
    deadline = time.time() + timeout if timeout else None
    captured = 0
    try:
        while not count or captured < count:
            if deadline and time.time() >= deadline:
                break
            try:
                raw, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            # On loopback the kernel delivers every frame twice (outgoing +
            # incoming). Drop the outgoing copy (PACKET_OUTGOING == 4).
            if addr[0] == "lo" and addr[2] == 4:
                continue
            if handler(raw, time.time()):
                captured += 1
    finally:
        sock.close()


def capture_scapy(iface: Optional[str], handler, count: int, timeout: Optional[float],
                  bpf: Optional[str]) -> None:
    from scapy.all import sniff, conf  # type: ignore
    state = {"n": 0}

    def _cb(p) -> None:
        if handler(bytes(p), float(p.time)):
            state["n"] += 1

    sniff(iface=iface or conf.iface, prn=_cb, store=False, filter=bpf, timeout=timeout,
          stop_filter=lambda _p: bool(count) and state["n"] >= count)


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401  type: ignore
        return True
    except Exception:
        return False


def is_admin() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
BANNER = r"""
  ____        _  __  __
 / ___| _ __ (_)/ _|/ _| ___ _ __   CodeAlpha - Basic Network Sniffer v{v}
 \___ \| '_ \| | |_| |_ / _ \ '__|  Capture . Dissect . Understand
  ___) | | | | |  _|  _|  __/ |
 |____/|_| |_|_|_| |_|  \___|_|
"""


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Capture and analyse network packets (Ethernet/IP/TCP/UDP/ICMP/ARP/DNS/HTTP/TLS).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  sudo python3 sniffer.py -c 20\n"
               "  sudo python3 sniffer.py -p dns -v\n"
               "  sudo python3 sniffer.py -f 'tcp port 80' --payload 128\n"
               "  sudo python3 sniffer.py -t 30 -w traffic.pcap")
    ap.add_argument("-i", "--iface", help="network interface (default: all / scapy default)")
    ap.add_argument("-c", "--count", type=int, default=0, help="packets to capture (0 = unlimited)")
    ap.add_argument("-t", "--timeout", type=float, help="stop after N seconds")
    ap.add_argument("-p", "--protocol", help="display filter: tcp, udp, icmp, arp, dns, http, tls, ipv6 ...")
    ap.add_argument("--host", help="only packets to/from this IP")
    ap.add_argument("--port", type=int, help="only packets to/from this port")
    ap.add_argument("-f", "--bpf", help="kernel BPF filter, e.g. 'tcp port 443' (scapy back-end)")
    ap.add_argument("--payload", type=int, default=0, metavar="N", help="hexdump first N payload bytes")
    ap.add_argument("-v", "--verbose", action="store_true", help="show every decoded header field")
    ap.add_argument("-w", "--write", metavar="FILE", help="save matching packets to a .pcap file")
    ap.add_argument("--backend", choices=["auto", "scapy", "socket"], default="auto")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        C.disable()
    if args.host:
        try:
            ipaddress.ip_address(args.host)
        except ValueError:
            print(f"[!] Invalid IP address: {args.host}", file=sys.stderr)
            return 2

    backend = args.backend
    if backend == "auto":
        backend = "scapy" if scapy_available() else "socket"
    if backend == "scapy" and not scapy_available():
        print("[!] scapy is not installed: pip install scapy", file=sys.stderr)
        return 2
    if args.bpf and backend != "scapy":
        print("[!] --bpf requires the scapy back-end; use -p/--host/--port instead.", file=sys.stderr)
        return 2
    if not is_admin():
        print("[!] Packet capture needs root/Administrator privileges (try: sudo).", file=sys.stderr)
        return 1

    print(f"{C.CYAN}{BANNER.format(v=__version__)}{C.RESET}")
    print(f"[*] Back-end: {backend} | Interface: {args.iface or 'all/default'} | "
          f"Count: {args.count or 'unlimited'} | Timeout: {args.timeout or 'none'}")
    filt = ", ".join(f"{k}={v}" for k, v in (("protocol", args.protocol), ("host", args.host),
                                             ("port", args.port), ("bpf", args.bpf)) if v)
    print(f"[*] Filters: {filt or 'none'}")
    print(f"[*] Press Ctrl+C to stop.\n")
    print(f"{C.BOLD}{'No.':<6} {'Time':>10}  {'Proto':<7} {'Source':>24}    "
          f"{'Destination':<24} {'Len':>6}  Info{C.RESET}")
    print("-" * 110)

    stats = Stats()
    writer = PcapWriter(args.write) if args.write else None
    start = time.time()
    seen = {"n": 0}

    def handle(raw: bytes, ts: float) -> bool:
        seen["n"] += 1
        pkt = dissect(raw, stats.count + 1, ts)
        if not matches(pkt, args.protocol, args.host, args.port):
            return False
        stats.add(pkt)
        print_packet(pkt, start, args.payload, args.verbose)
        if writer:
            writer.write(raw, ts)
        return True

    try:
        if backend == "scapy":
            capture_scapy(args.iface, handle, args.count, args.timeout, args.bpf)
        else:
            capture_socket(args.iface, handle, args.count, args.timeout)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    except PermissionError:
        print("[!] Permission denied: run as root/Administrator.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"[!] Capture error: {exc}", file=sys.stderr)
        return 1
    finally:
        if writer:
            writer.close()
            print(f"[*] Saved {stats.count} packets to {args.write} (open with Wireshark).")

    stats.report()
    return 0


if __name__ == "__main__":
    sys.exit(main())
