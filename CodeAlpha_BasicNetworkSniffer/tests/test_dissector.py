"""Unit tests for the packet dissector (no root needed): python3 -m unittest -v"""
import os
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sniffer  # noqa: E402

MAC_A = bytes.fromhex("aabbccddeeff")
MAC_B = bytes.fromhex("112233445566")


def eth(ethertype: int, body: bytes) -> bytes:
    return MAC_B + MAC_A + struct.pack("!H", ethertype) + body


def ipv4(proto: int, body: bytes, src="192.168.1.10", dst="8.8.8.8", ttl=64) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1, 0x4000, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + body


def tcp(sport, dport, flags, payload=b"") -> bytes:
    return struct.pack("!HHIIHHHH", sport, dport, 1000, 0, (5 << 12) | flags, 64240, 0, 0) + payload


def udp(sport, dport, payload=b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name: str, qtype=1) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


class DissectorTests(unittest.TestCase):
    def test_ethernet_ipv4_tcp_syn(self):
        p = sniffer.dissect(eth(0x0800, ipv4(6, tcp(51000, 443, 0x02))), 1, 0.0)
        self.assertEqual(p.src_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual((p.src_ip, p.dst_ip, p.ttl), ("192.168.1.10", "8.8.8.8", 64))
        self.assertEqual((p.transport, p.src_port, p.dst_port), ("TCP", 51000, 443))
        self.assertIn("SYN", p.info)
        self.assertIn("HTTPS", p.info)

    def test_http_request(self):
        req = b"GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n"
        p = sniffer.dissect(eth(0x0800, ipv4(6, tcp(50000, 80, 0x18, req))), 1, 0.0)
        self.assertEqual(p.protocol, "HTTP")
        self.assertIn("GET /login HTTP/1.1", p.info)
        self.assertIn("example.com", p.info)

    def test_dns_query(self):
        p = sniffer.dissect(eth(0x0800, ipv4(17, udp(53000, 53, dns_query("codealpha.tech")))), 1, 0.0)
        self.assertEqual(p.protocol, "DNS")
        self.assertIn("codealpha.tech", p.info)
        self.assertIn(" A", p.info)

    def test_dns_response_with_compression(self):
        q = dns_query("example.com")
        hdr = struct.pack("!HHHHHH", 0xBEEF, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton("93.184.216.34")
        p = sniffer.dissect(eth(0x0800, ipv4(17, udp(53, 53000, hdr + q[12:] + answer))), 1, 0.0)
        self.assertIn("response", p.info)
        self.assertIn("93.184.216.34", p.info)

    def test_icmp_echo(self):
        icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping"
        p = sniffer.dissect(eth(0x0800, ipv4(1, icmp)), 1, 0.0)
        self.assertEqual(p.protocol, "ICMP")
        self.assertIn("Echo Request", p.info)

    def test_arp_request(self):
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + MAC_A + socket.inet_aton("192.168.1.10") \
            + b"\x00" * 6 + socket.inet_aton("192.168.1.1")
        p = sniffer.dissect(eth(0x0806, arp), 1, 0.0)
        self.assertEqual(p.protocol, "ARP")
        self.assertEqual(p.info, "Who has 192.168.1.1? Tell 192.168.1.10")

    def test_ipv6_udp(self):
        body = udp(5353, 5353, b"")
        hdr = struct.pack("!IHBB", 6 << 28, len(body), 17, 255) + \
            socket.inet_pton(socket.AF_INET6, "fe80::1") + socket.inet_pton(socket.AF_INET6, "ff02::fb")
        p = sniffer.dissect(eth(0x86DD, hdr + body), 1, 0.0)
        self.assertEqual((p.src_ip, p.dst_ip, p.transport), ("fe80::1", "ff02::fb", "UDP"))

    def test_tls_client_hello_sni(self):
        sni = b"secure.example.org"
        ext_sni = struct.pack("!HH", 0, len(sni) + 5) + struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni
        hello = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" \
            + struct.pack("!H", len(ext_sni)) + ext_sni
        hs = b"\x01" + len(hello).to_bytes(3, "big") + hello
        record = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
        p = sniffer.dissect(eth(0x0800, ipv4(6, tcp(50001, 443, 0x18, record))), 1, 0.0)
        self.assertEqual(p.protocol, "TLS")
        self.assertIn("ClientHello", p.info)
        self.assertIn("secure.example.org", p.info)

    def test_truncated_frames_do_not_crash(self):
        frame = eth(0x0800, ipv4(6, tcp(1, 2, 0x02)))
        for cut in range(len(frame)):
            sniffer.dissect(frame[:cut], 1, 0.0)

    def test_filters(self):
        p = sniffer.dissect(eth(0x0800, ipv4(17, udp(53000, 53, dns_query("a.com")))), 1, 0.0)
        self.assertTrue(sniffer.matches(p, "dns", None, None))
        self.assertTrue(sniffer.matches(p, "udp", "8.8.8.8", 53))
        self.assertFalse(sniffer.matches(p, "tcp", None, None))
        self.assertFalse(sniffer.matches(p, None, "1.1.1.1", None))

    def test_pcap_writer(self):
        frame = eth(0x0800, ipv4(6, tcp(1, 2, 0x02)))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.pcap")
            w = sniffer.PcapWriter(path)
            w.write(frame, 1700000000.5)
            w.close()
            with open(path, "rb") as fh:
                data = fh.read()
        self.assertEqual(struct.unpack("<I", data[:4])[0], 0xA1B2C3D4)
        self.assertEqual(len(data), 24 + 16 + len(frame))
        self.assertEqual(data[40:], frame)


if __name__ == "__main__":
    unittest.main(verbosity=2)
