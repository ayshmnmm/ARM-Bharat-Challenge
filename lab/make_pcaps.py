"""Generate synthetic lab captures for testing and demos, without sending a single packet.

Some threats can't be simulated live without emitting suspicious traffic upstream through the
campus network (phishing lookups, C2 contact, floods). These pcaps are written to disk only and
fed through the normal pipeline with `python -m netwatch replay`.

    python lab/make_pcaps.py tests/fixtures
"""

from __future__ import annotations

import os
import random
import struct
import sys
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, wrpcap

ROUTER = "192.168.1.1"
ROUTER_MAC = "60:a4:b7:e5:ba:ae"
PHONE, PHONE_MAC = "192.168.1.50", "02:11:22:33:44:55"     # randomised-MAC phone
LAPTOP, LAPTOP_MAC = "192.168.1.60", "70:d8:23:00:00:01"   # Intel OUI laptop
# Start time of every capture. Set NETWATCH_LAB_T0 (Unix time) to stamp replayed alerts as recent.
T0 = float(os.environ.get("NETWATCH_LAB_T0", 1_794_000_000.0))
random.seed(7)


class Clock:
    def __init__(self, t: float = T0):
        self.t = t

    def tick(self, dt: float = 0.001) -> float:
        self.t += dt
        return self.t


def _pkt(src_mac, dst_mac, ip, l4, t):
    p = Ether(src=src_mac, dst=dst_mac) / ip / l4
    p.time = t
    return p


def client_hello(sni: str) -> bytes:
    """Minimal TLS 1.2/1.3-style ClientHello carrying an SNI extension."""
    name = sni.encode()
    sni_list = struct.pack("!BH", 0, len(name)) + name
    ext_sni = struct.pack("!HHH", 0x0000, len(sni_list) + 2, len(sni_list)) + sni_list
    ext_versions = struct.pack("!HHB", 0x002B, 3, 2) + b"\x03\x04"
    exts = ext_sni + ext_versions
    body = (b"\x03\x03" + bytes(random.getrandbits(8) for _ in range(32)) + b"\x00"
            + struct.pack("!H", 4) + b"\x13\x01\xc0\x2f" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def server_hello() -> bytes:
    """Minimal TLS 1.3 ServerHello: Suricata logs the TLS record once it sees the server's reply."""
    exts = struct.pack("!HHH", 0x002B, 2, 0x0304)
    body = (b"\x03\x03" + bytes(random.getrandbits(8) for _ in range(32)) + b"\x00"
            + b"\x13\x01" + b"\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def tcp_session(clk, cip, cmac, sip, smac, sport, dport, payload=b"", reply=b"", gap=0.002):
    """Full handshake, optional request/response, FIN teardown."""
    c_isn, s_isn = random.randrange(2**31), random.randrange(2**31)
    ip_c, ip_s = IP(src=cip, dst=sip), IP(src=sip, dst=cip)
    pk = [
        _pkt(cmac, smac, ip_c, TCP(sport=sport, dport=dport, flags="S", seq=c_isn), clk.tick(gap)),
        _pkt(smac, cmac, ip_s, TCP(sport=dport, dport=sport, flags="SA", seq=s_isn, ack=c_isn + 1), clk.tick(gap)),
        _pkt(cmac, smac, ip_c, TCP(sport=sport, dport=dport, flags="A", seq=c_isn + 1, ack=s_isn + 1), clk.tick(gap)),
    ]
    cs, ss = c_isn + 1, s_isn + 1
    if payload:
        pk.append(_pkt(cmac, smac, ip_c, TCP(sport=sport, dport=dport, flags="PA", seq=cs, ack=ss) / payload, clk.tick(gap)))
        cs += len(payload)
        pk.append(_pkt(smac, cmac, ip_s, TCP(sport=dport, dport=sport, flags="A", seq=ss, ack=cs), clk.tick(gap)))
    if reply:
        pk.append(_pkt(smac, cmac, ip_s, TCP(sport=dport, dport=sport, flags="PA", seq=ss, ack=cs) / reply, clk.tick(gap)))
        ss += len(reply)
        pk.append(_pkt(cmac, smac, ip_c, TCP(sport=sport, dport=dport, flags="A", seq=cs, ack=ss), clk.tick(gap)))
    pk += [
        _pkt(cmac, smac, ip_c, TCP(sport=sport, dport=dport, flags="FA", seq=cs, ack=ss), clk.tick(gap)),
        _pkt(smac, cmac, ip_s, TCP(sport=dport, dport=sport, flags="FA", seq=ss, ack=cs + 1), clk.tick(gap)),
        _pkt(cmac, smac, ip_c, TCP(sport=sport, dport=dport, flags="A", seq=cs + 1, ack=ss + 1), clk.tick(gap)),
    ]
    return pk


def dns_lookup(clk, cip, cmac, name, answer_ip):
    sport, qid = random.randrange(20000, 60000), random.randrange(65536)
    q = _pkt(cmac, ROUTER_MAC, IP(src=cip, dst=ROUTER), UDP(sport=sport, dport=53) /
             DNS(id=qid, rd=1, qd=DNSQR(qname=name)), clk.tick())
    a = _pkt(ROUTER_MAC, cmac, IP(src=ROUTER, dst=cip), UDP(sport=53, dport=sport) /
             DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=60, rdata=answer_ip)),
             clk.tick())
    return [q, a]


def phishing_visit() -> list:
    """Phone looks up a (reserved, lab-listed) phishing domain and opens it over HTTPS."""
    clk = Clock()
    name, ip = "login-verify-account.netwatch-lab.test", "203.0.113.10"   # TEST-NET-3
    pk = dns_lookup(clk, PHONE, PHONE_MAC, name, ip)
    pk += tcp_session(clk, PHONE, PHONE_MAC, ip, ROUTER_MAC, 51515, 443, client_hello(name), server_hello())
    # plus some benign traffic that must not alert
    pk += dns_lookup(clk, PHONE, PHONE_MAC, "www.example.com", "93.184.215.14")
    pk += tcp_session(clk, PHONE, PHONE_MAC, "93.184.215.14", ROUTER_MAC, 51516, 443, client_hello("www.example.com"), server_hello())
    return pk


def phishing_lookup_only() -> list:
    clk = Clock()
    return dns_lookup(clk, LAPTOP, LAPTOP_MAC, "netwatch-lab-phish.test", "203.0.113.20")


def syn_flood() -> list:
    """500 SYNs to the router's port 3000 in ~1 s from one LAN host, never completed."""
    clk = Clock()
    return [
        _pkt(LAPTOP_MAC, ROUTER_MAC, IP(src=LAPTOP, dst=ROUTER),
             TCP(sport=random.randrange(1024, 65535), dport=3000, flags="S", seq=random.randrange(2**31)), clk.tick(0.002))
        for _ in range(500)
    ]


def ssh_bruteforce() -> list:
    """40 short SSH sessions (banner + ~1 KB each way) to the router within a minute."""
    clk = Clock()
    pk = []
    for i in range(40):
        pk += tcp_session(clk, LAPTOP, LAPTOP_MAC, ROUTER, ROUTER_MAC, 40000 + i, 22,
                          b"SSH-2.0-libssh_0.9.6\r\n" + b"\x00" * 1000, b"SSH-2.0-OpenSSH_10.0\r\n" + b"\x00" * 1000)
        clk.tick(1.2)
    return pk


def host_sweep() -> list:
    """ARP-less ping-style TCP sweep of 30 LAN addresses on port 80."""
    clk = Clock()
    return [
        _pkt(LAPTOP_MAC, "ff:ff:ff:ff:ff:ff", IP(src=LAPTOP, dst=f"192.168.1.{h}"),
             TCP(sport=45000 + h, dport=80, flags="S"), clk.tick(0.01))
        for h in range(100, 130)
    ]


CAMERA, CAMERA_MAC = "192.168.1.70", "24:0a:c4:00:00:07"    # Espressif OUI: an IoT camera/plug


def beaconing() -> list:
    """An IoT device phoning home every 60 s (+-1 s) for 20 minutes: tiny TLS sessions to one
    internet address (TEST-NET-3, never routed). The rhythm of malware check-ins (C2 beaconing)."""
    clk = Clock()
    pk = []
    for i in range(20):
        pk += tcp_session(clk, CAMERA, CAMERA_MAC, "203.0.113.66", ROUTER_MAC, 41000 + i, 443,
                          client_hello("cdn-update.netwatch-lab.test"), server_hello())
        clk.tick(60 + random.uniform(-1, 1))
    return pk


def _random_label(n: int) -> str:
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def dga_lookups() -> list:
    """Malware trying algorithm-generated domains: 25 random names, all non-existent (NXDOMAIN)."""
    clk = Clock()
    pk = []
    for _ in range(25):
        name = _random_label(random.randint(12, 18)) + random.choice([".com", ".net", ".info"])
        sport, qid = random.randrange(20000, 60000), random.randrange(65536)
        pk.append(_pkt(LAPTOP_MAC, ROUTER_MAC, IP(src=LAPTOP, dst=ROUTER), UDP(sport=sport, dport=53) /
                       DNS(id=qid, rd=1, qd=DNSQR(qname=name)), clk.tick(0.4)))
        pk.append(_pkt(ROUTER_MAC, LAPTOP_MAC, IP(src=ROUTER, dst=LAPTOP), UDP(sport=53, dport=sport) /
                       DNS(id=qid, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=name)), clk.tick(0.01)))
    pk += dns_lookup(clk, LAPTOP, LAPTOP_MAC, "www.example.com", "93.184.215.14")  # normal, must not count
    return pk


def dns_tunnel() -> list:
    """Data smuggled out inside DNS names: 40 TXT queries with long encoded labels under one domain."""
    import base64
    clk = Clock()
    pk = []
    for i in range(40):
        chunk = base64.b32encode(bytes(random.getrandbits(8) for _ in range(30))).decode().strip("=").lower()
        name = f"{chunk}.{i}.t.exfil-lab.example"
        sport, qid = random.randrange(20000, 60000), random.randrange(65536)
        pk.append(_pkt(LAPTOP_MAC, ROUTER_MAC, IP(src=LAPTOP, dst=ROUTER), UDP(sport=sport, dport=53) /
                       DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype="TXT")), clk.tick(0.5)))
        pk.append(_pkt(ROUTER_MAC, LAPTOP_MAC, IP(src=ROUTER, dst=LAPTOP), UDP(sport=53, dport=sport) /
                       DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name, qtype="TXT"),
                           an=DNSRR(rrname=name, type="TXT", ttl=0, rdata="ok")), clk.tick(0.01)))
    return pk


NMAP_TOP10 = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389]   # `nmap --top-ports 10`


def lateral_probe() -> list:
    """Worm-style probing: an infected camera checks nmap's top-10 login/file-sharing ports on three other
    devices in a few seconds. 10 ports per device and 3 devices stay under both scan rules; the ML detector
    adds the probes up. Packets copy the shape Suricata logged for real nmap SYN probes on this network:
    a 60-byte SYN (MSS option, padded) answered by a 54-byte RST."""
    from scapy.all import Padding
    clk = Clock(T0 + 1800)   # half an hour after the other captures: a separate incident
    pk = []
    for host, mac in ((ROUTER, ROUTER_MAC), (PHONE, PHONE_MAC), (LAPTOP, LAPTOP_MAC)):
        for port in NMAP_TOP10:
            seq = random.randrange(2**31)
            syn = TCP(sport=51234, dport=port, flags="S", seq=seq, window=1024, options=[("MSS", 1460)])
            pk.append(_pkt(CAMERA_MAC, mac, IP(src=CAMERA, dst=host, ttl=44), syn / Padding(load=b"\x00" * 2),
                           clk.tick(0.08)))
            pk.append(_pkt(mac, CAMERA_MAC, IP(src=host, dst=CAMERA),
                           TCP(sport=port, dport=51234, flags="RA", seq=0, ack=seq + 1, window=0), clk.tick(0.0003)))
    return pk


CAPTURES = {
    "lab_phishing_visit.pcap": phishing_visit,
    "lab_phishing_lookup.pcap": phishing_lookup_only,
    "lab_syn_flood.pcap": syn_flood,
    "lab_ssh_bruteforce.pcap": ssh_bruteforce,
    "lab_host_sweep.pcap": host_sweep,
    "lab_beaconing.pcap": beaconing,
    "lab_dga.pcap": dga_lookups,
    "lab_dns_tunnel.pcap": dns_tunnel,
    "lab_lateral_probe.pcap": lateral_probe,   # last, so the random draws of the others are unchanged
}


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, fn in CAPTURES.items():
        wrpcap(str(out / name), fn())
        print(out / name)


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures"))
