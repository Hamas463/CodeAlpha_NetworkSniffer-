#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1
Advanced Network Sniffer (CLI)
Author: Hamas Ahmad Furqan

Live packet sniffer with protocol decoding, port/service resolution,
host discovery, live statistics (top talkers, conversations, top services,
per-host bandwidth), colored output, and PCAP export.

Uses BOTH scapy (packet capture) and socket (port -> service name and
reverse-DNS hostname lookups), matching the CodeAlpha task requirements.

USAGE (run with root privileges):
    sudo python3 network_sniffer.py -i eth0             # sniff on eth0 (Kali/VMware)
    sudo python3 network_sniffer.py -i eth0 -c 100      # stop after 100 packets
    sudo python3 network_sniffer.py -i eth0 -f "tcp port 443"
    sudo python3 network_sniffer.py -i eth0 --resolve   # reverse-DNS IPs -> hostnames
    sudo python3 network_sniffer.py -i eth0 -w out.pcap # save to pcap for Wireshark
    sudo python3 network_sniffer.py --scan              # discover hosts on your subnet
    sudo python3 network_sniffer.py -i eth0 -p          # promiscuous mode

ETHICS / LEGAL:
    Only run this on networks you own or are explicitly authorised to monitor.
"""

import argparse
import signal
import socket
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import (
        sniff, wrpcap, arping, conf, get_if_addr,
        IP, IPv6, TCP, UDP, ICMP, ARP, DNSQR, Raw,
    )
except ImportError:
    raise SystemExit("scapy is not installed. On Kali:  sudo apt install python3-scapy")


# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"; DIM = "\033[2m"; BOLD = "\033[1m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"


PROTO_COLORS = {
    "TCP": C.GREEN, "UDP": C.BLUE, "ICMP": C.YELLOW,
    "ARP": C.MAGENTA, "DNS": C.CYAN, "HTTP": C.BOLD + C.CYAN,
}

USE_COLOR = True
RESOLVE_HOSTS = False   # toggled by --resolve


def color(text, code):
    return f"{code}{text}{C.RESET}" if USE_COLOR else text


# ---------------------------------------------------------------------------
# socket-based enrichment: port -> service name, IP -> hostname (cached)
# ---------------------------------------------------------------------------
_service_cache = {}
_host_cache = {}


def service_name(port, proto):
    """Map a port number to its service name (e.g. 443 -> 'https') via socket."""
    if port is None or proto is None:
        return None
    key = (port, proto)
    if key in _service_cache:
        return _service_cache[key]
    try:
        name = socket.getservbyport(port, proto)
    except (OSError, TypeError, OverflowError):
        name = None
    _service_cache[key] = name
    return name


def resolve_host(ip):
    """Reverse-DNS an IP to a hostname via socket (only when --resolve is set)."""
    if not RESOLVE_HOSTS:
        return None
    if ip in _host_cache:
        return _host_cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = None
    _host_cache[ip] = name
    return name


def fmt_endpoint(ip, port, proto_l):
    """Format an endpoint as host[:port[/service]], using socket lookups."""
    shown = resolve_host(ip) or ip
    if port is None:
        return shown
    svc = service_name(port, proto_l)
    return f"{shown}:{port}" + (f"/{svc}" if svc else "")


def classify_service(sport, dport, proto_l):
    """Best-guess the 'service' of a flow for statistics."""
    for p in (dport, sport):
        s = service_name(p, proto_l)
        if s:
            return s
    if sport is not None and dport is not None:
        return f"{proto_l or ''}:{min(sport, dport)}"
    return None


# ---------------------------------------------------------------------------
# Live statistics
# ---------------------------------------------------------------------------
stats = {
    "total": 0, "bytes": 0,
    "protocols": Counter(),
    "talkers": Counter(),
    "conversations": Counter(),
    "host_bytes": Counter(),
    "services": Counter(),        # service/port -> packet count
    "start": None,
}


def preview_payload(packet, length=48):
    if Raw in packet:
        data = bytes(packet[Raw].load)
        return "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:length])
    return ""


def decode_dns(packet):
    if packet.haslayer(DNSQR):
        try:
            qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
            return f"DNS query -> {qname}"
        except Exception:
            return "DNS query"
    return None


def decode_http(packet):
    if Raw not in packet:
        return None
    try:
        data = bytes(packet[Raw].load).decode(errors="replace")
    except Exception:
        return None
    first = data.split("\r\n", 1)[0]
    methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
    if first.startswith(methods):
        host = ""
        for line in data.split("\r\n"):
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return f"HTTP {first}" + (f"  (Host: {host})" if host else "")
    return None


def process_packet(packet):
    if stats["start"] is None:
        stats["start"] = datetime.now()
    size = len(packet)
    stats["total"] += 1
    stats["bytes"] += size
    ts = datetime.now().strftime("%H:%M:%S")

    # --- ARP ---
    if ARP in packet:
        stats["protocols"]["ARP"] += 1
        op = "who-has" if packet[ARP].op == 1 else "is-at"
        print(f"[{ts}] {color('ARP ', PROTO_COLORS['ARP'])} {packet[ARP].psrc} -> {packet[ARP].pdst}  ({op})")
        return

    # --- IP layer ---
    if IP in packet:
        ip_layer = packet[IP]
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
    else:
        stats["protocols"]["Other"] += 1
        return

    src, dst = ip_layer.src, ip_layer.dst
    stats["talkers"][src] += 1
    stats["host_bytes"][src] += size
    stats["host_bytes"][dst] += size
    stats["conversations"][tuple(sorted((src, dst)))] += size

    proto = "Other"; sport = dport = None; flags = ""; proto_l = None
    if TCP in packet:
        proto, proto_l = "TCP", "tcp"
        sport, dport = packet[TCP].sport, packet[TCP].dport
        flags = str(packet[TCP].flags)
    elif UDP in packet:
        proto, proto_l = "UDP", "udp"
        sport, dport = packet[UDP].sport, packet[UDP].dport
    elif ICMP in packet:
        proto = "ICMP"

    stats["protocols"][proto] += 1
    svc = classify_service(sport, dport, proto_l)
    if svc:
        stats["services"][svc] += 1

    decoded = decode_dns(packet) or decode_http(packet)
    display_proto = ("DNS" if (decoded and decoded.startswith("DNS"))
                     else "HTTP" if (decoded and decoded.startswith("HTTP"))
                     else proto)

    endpoint_src = fmt_endpoint(src, sport, proto_l)
    endpoint_dst = fmt_endpoint(dst, dport, proto_l)
    proto_col = PROTO_COLORS.get(display_proto, "")

    line = (f"[{ts}] {color(f'{display_proto:<4}', proto_col)} "
            f"{endpoint_src:<30} -> {endpoint_dst:<30} {size:>4}B")
    if flags:
        line += color(f"  flags={flags}", C.DIM)
    if decoded:
        line += "  " + color(decoded, C.CYAN)
    else:
        payload = preview_payload(packet)
        if payload:
            line += color(f"  data={payload!r}", C.DIM)
    print(line)


def print_summary():
    if stats["total"] == 0:
        print("\nNo packets captured.")
        return
    duration = (datetime.now() - stats["start"]).total_seconds() if stats["start"] else 0
    rate = stats["total"] / duration if duration > 0 else 0

    print("\n" + "=" * 60)
    print(color("Capture Summary", C.BOLD))
    print("=" * 60)
    print(f"  Packets captured : {stats['total']}")
    print(f"  Total data       : {stats['bytes'] / 1024:.1f} KB")
    print(f"  Duration         : {duration:.1f}s  ({rate:.1f} pkt/s)")

    print("\n  Protocol breakdown:")
    for proto, count in stats["protocols"].most_common():
        print(f"    {proto:<6} {count:>6}  ({count / stats['total'] * 100:4.1f}%)")

    print("\n  Top services / ports:")
    for svc, count in stats["services"].most_common(8):
        print(f"    {svc:<16} {count:>6} packets")

    print("\n  Top talkers (by source IP):")
    for ip, count in stats["talkers"].most_common(5):
        print(f"    {ip:<22} {count:>6} packets")

    print("\n  Top conversations (by data volume):")
    for (a, b), byts in stats["conversations"].most_common(5):
        print(f"    {a:<16} <-> {b:<16} {byts / 1024:8.1f} KB")

    print("\n  Bandwidth per host (sent + received):")
    for ip, byts in stats["host_bytes"].most_common(8):
        print(f"    {ip:<18} {byts / 1024:8.1f} KB")


def discover_hosts(subnet):
    if not subnet:
        try:
            local_ip = get_if_addr(conf.iface)
            subnet = local_ip.rsplit(".", 1)[0] + ".0/24"
        except Exception:
            raise SystemExit("Could not auto-detect subnet. Pass one, e.g. --scan 192.168.1.0/24")

    print(f"Scanning {subnet} for live hosts (ARP)...\n")
    answered, _ = arping(subnet, verbose=0, timeout=2)
    hosts = [(rcv.psrc, rcv.hwsrc) for _, rcv in answered]
    hosts.sort(key=lambda x: tuple(int(o) for o in x[0].split(".")))

    print(f"{'IP Address':<18} {'MAC Address':<20} {'Hostname'}")
    print("-" * 60)
    for ip, mac in hosts:
        name = resolve_host(ip) or ""
        print(f"{ip:<18} {mac:<20} {name}")
    print(f"\n{len(hosts)} host(s) responded on {subnet}.")


def main():
    global USE_COLOR, RESOLVE_HOSTS

    parser = argparse.ArgumentParser(description="Advanced network sniffer (CodeAlpha Task 1)")
    parser.add_argument("-i", "--iface", help="Interface to sniff (e.g. eth0, br0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packets to capture (0=unlimited)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    parser.add_argument("-p", "--promisc", action="store_true", help="Enable promiscuous mode")
    parser.add_argument("-w", "--write", metavar="FILE", help="Save captured packets to a .pcap file")
    parser.add_argument("--resolve", action="store_true",
                        help="Reverse-DNS IPs to hostnames via socket (slower)")
    parser.add_argument("--scan", nargs="?", const="", metavar="CIDR",
                        help="Discover hosts on your subnet, then exit")
    parser.add_argument("--exclude", nargs="*", default=[], metavar="IP",
                        help="Ignore traffic to/from these IPs")
    parser.add_argument("--exclude-self", action="store_true",
                        help="Ignore this host's own traffic (useful on a SPAN/tap)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    USE_COLOR = sys.stdout.isatty() and not args.no_color
    RESOLVE_HOSTS = args.resolve
    if RESOLVE_HOSTS:
        socket.setdefaulttimeout(1.0)   # keep reverse-DNS from hanging the sniffer

    if args.scan is not None:
        discover_hosts(args.scan)
        return

    excludes = list(args.exclude)
    if args.exclude_self:
        try:
            own = get_if_addr(args.iface or conf.iface)
            if own and own != "0.0.0.0":
                excludes.append(own)
                print(f"Excluding own traffic ({own}).")
        except Exception:
            print("Could not detect own IP for --exclude-self; continuing without it.")

    parts = []
    if args.filter:
        parts.append(f"({args.filter})")
    parts += [f"not host {ip}" for ip in excludes]
    bpf = " and ".join(parts) if parts else None

    captured = []

    def handler(pkt):
        process_packet(pkt)
        if args.write:
            captured.append(pkt)

    def on_exit(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, on_exit)

    mode = "promiscuous" if args.promisc else "normal"
    print(f"Starting sniffer in {mode} mode on '{args.iface or 'default'}'... Ctrl+C to stop.\n")
    try:
        sniff(iface=args.iface, prn=handler, count=args.count,
              filter=bpf, promisc=args.promisc, store=False)
    except PermissionError:
        raise SystemExit("Permission denied. Run with sudo.")
    except KeyboardInterrupt:
        pass
    finally:
        print_summary()
        if args.write and captured:
            wrpcap(args.write, captured)
            print(f"\nSaved {len(captured)} packets to {args.write} (open it in Wireshark).")


if __name__ == "__main__":
    main()
