#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Internship — Task 1
Basic Network Sniffer
Author : Prathamesh Tikle
Tool   : Scapy
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from datetime import datetime
import argparse
import sys

# ── Colour codes for terminal output ─────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

BANNER = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════╗
║        CodeAlpha — Basic Network Sniffer             ║
║        Author : Prathamesh Tikle                     ║
║        Tool   : Scapy                                ║
╚══════════════════════════════════════════════════════╝{RESET}
"""

# ── Packet counter ────────────────────────────────────────────────────────────
packet_count = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "dns": 0, "other": 0}


def get_protocol(pkt):
    """Return human-readable protocol name."""
    if pkt.haslayer(DNS):   return "DNS"
    if pkt.haslayer(TCP):   return "TCP"
    if pkt.haslayer(UDP):   return "UDP"
    if pkt.haslayer(ICMP):  return "ICMP"
    return "OTHER"


def get_flags(pkt):
    """Return TCP flag string e.g. [SYN, ACK]."""
    if not pkt.haslayer(TCP):
        return ""
    flags = pkt[TCP].flags
    flag_map = {
        "F": "FIN", "S": "SYN", "R": "RST",
        "P": "PSH", "A": "ACK", "U": "URG",
    }
    active = [name for bit, name in flag_map.items() if bit in str(flags)]
    return f"[{', '.join(active)}]" if active else ""


def get_payload(pkt, max_len=60):
    """Extract and truncate raw payload."""
    if pkt.haslayer(Raw):
        try:
            raw = pkt[Raw].load.decode("utf-8", errors="replace").strip()
            raw = raw.replace("\n", " ").replace("\r", "")
            return raw[:max_len] + ("..." if len(raw) > max_len else "")
        except Exception:
            return "<binary payload>"
    return ""


def colour_for_proto(proto):
    return {
        "TCP":   GREEN,
        "UDP":   YELLOW,
        "ICMP":  RED,
        "DNS":   CYAN,
        "OTHER": WHITE,
    }.get(proto, WHITE)


def process_packet(pkt):
    """Callback — called for every captured packet."""
    if not pkt.haslayer(IP):
        return  # skip non-IP packets

    packet_count["total"] += 1
    proto = get_protocol(pkt)
    packet_count[proto.lower() if proto.lower() in packet_count else "other"] += 1

    ts      = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    src_ip  = pkt[IP].src
    dst_ip  = pkt[IP].dst
    ttl     = pkt[IP].ttl
    length  = len(pkt)
    col     = colour_for_proto(proto)

    # Port info
    src_port = dst_port = ""
    if pkt.haslayer(TCP):
        src_port = f":{pkt[TCP].sport}"
        dst_port = f":{pkt[TCP].dport}"
    elif pkt.haslayer(UDP):
        src_port = f":{pkt[UDP].sport}"
        dst_port = f":{pkt[UDP].dport}"

    flags   = get_flags(pkt)
    payload = get_payload(pkt)

    # DNS query detail
    dns_info = ""
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            dns_info = f" → Query: {pkt[DNSQR].qname.decode()}"
        except Exception:
            pass

    print(
        f"{col}[{ts}] {BOLD}{proto:<5}{RESET}{col} "
        f"{src_ip}{src_port} → {dst_ip}{dst_port} "
        f"| TTL:{ttl} Len:{length}B "
        f"{flags}{dns_info}"
        f"{(' | ' + payload) if payload else ''}"
        f"{RESET}"
    )


def print_summary():
    """Print capture statistics."""
    print(f"\n{CYAN}{BOLD}{'─'*54}")
    print("  Capture Summary")
    print(f"{'─'*54}{RESET}")
    for key, val in packet_count.items():
        bar = "█" * min(val, 40)
        print(f"  {key.upper():<8} {val:>5}  {GREEN}{bar}{RESET}")
    print(f"{CYAN}{'─'*54}{RESET}\n")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="CodeAlpha Basic Network Sniffer — Prathamesh Tikle"
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to sniff on (e.g. eth0, wlan0). Default: auto")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter string (e.g. 'tcp', 'udp port 53', 'host 8.8.8.8')")
    parser.add_argument("-p", "--protocol", default="all",
                        choices=["all", "tcp", "udp", "icmp", "dns"],
                        help="Protocol filter shortcut")
    args = parser.parse_args()

    # Build BPF filter
    bpf = args.filter
    if args.protocol != "all" and not bpf:
        bpf = {"tcp": "tcp", "udp": "udp",
               "icmp": "icmp", "dns": "udp port 53"}[args.protocol]

    print(f"{WHITE}  Interface : {CYAN}{args.interface or 'auto-detect'}{RESET}")
    print(f"{WHITE}  Count     : {CYAN}{args.count or 'unlimited'}{RESET}")
    print(f"{WHITE}  BPF Filter: {CYAN}{bpf or 'none'}{RESET}")
    print(f"{WHITE}  Protocol  : {CYAN}{args.protocol}{RESET}")
    print(f"\n{YELLOW}  Starting capture... Press Ctrl+C to stop.{RESET}\n")
    print(f"{'─'*90}")

    try:
        sniff(
            iface=args.interface,
            filter=bpf,
            prn=process_packet,
            count=args.count,
            store=False,
        )
    except KeyboardInterrupt:
        print(f"\n{YELLOW}  Capture stopped by user.{RESET}")
    except PermissionError:
        print(f"\n{RED}  Permission denied — run with sudo.{RESET}")
        sys.exit(1)
    finally:
        print_summary()


if __name__ == "__main__":
    main()
