# feature_extractor.py - interface auto-detection, no hardcoded GUID
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ARP, ICMP, get_if_list, conf
from scapy.all import Ether, srp
import numpy as np
from collections import defaultdict
import time


SERVICE_PORTS = {
    "HTTP": {80}, "HTTPS": {443}, "DNS": {53}, "Telnet": {23},
    "SMTP": {25}, "SSH": {22}, "IRC": {194}, "DHCP": {67, 68}, "FTP": {20, 21},
}

TCP_FIN = 0x01; TCP_SYN = 0x02; TCP_RST = 0x04; TCP_PSH = 0x08
TCP_ACK = 0x10; TCP_URG = 0x20; TCP_ECE = 0x40; TCP_CWR = 0x80


def pick_best_interface():
    """Choose an interface that actually routes traffic, not a dead adapter."""
    try:
        if conf.iface:
            return conf.iface
    except Exception:
        pass
    ifaces = get_if_list()
    for keyword in ("Wi-Fi", "Ethernet", "wlan", "eth", "en0", "en1"):
        for i in ifaces:
            if keyword.lower() in i.lower():
                return i
    return ifaces[0] if ifaces else None


def stimulate_device(ip, iface):
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        srp(pkt, timeout=2, iface=iface, verbose=False)
        time.sleep(0.5)
    except Exception as e:
        print(f"[!] stimulate failed: {e}")


def pkt_flow_key(pkt):
    src = dst = "unknown"; proto = 0
    if IP in pkt:
        src, dst, proto = pkt[IP].src, pkt[IP].dst, pkt[IP].proto
    sport = dport = None
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    return (src, dst, sport, dport, proto)


def capture_packets_filtered(duration=10, iface=None, filter_expr=None, pcap_file=None):
    if pcap_file:
        return rdpcap(pcap_file)
    if iface is None:
        iface = pick_best_interface()
    if iface is None:
        print("[!] No usable interface found")
        return []

    target_ip = None
    if filter_expr and filter_expr.startswith("host "):
        target_ip = filter_expr.split(" ", 1)[1]
        print(f"[*] Stimulating {target_ip} on {iface}")
        stimulate_device(target_ip, iface)

    try:
        print(f"[*] Sniffing {duration}s on {iface} filter={filter_expr}")
        packets = sniff(timeout=duration, iface=iface, filter=filter_expr)
        print(f"[*] Captured {len(packets)} packets")
        if len(packets) == 0 and target_ip:
            stimulate_device(target_ip, iface)
            packets = sniff(timeout=max(3, duration // 2), iface=iface, filter=filter_expr)
            print(f"[*] Retry captured {len(packets)} packets")
        return packets
    except PermissionError:
        print("[!] Permission denied — run as Administrator / sudo")
        return []
    except Exception as e:
        print(f"[!] Sniff failed: {e}")
        return []


def group_packets_to_flows(packets):
    flows = defaultdict(list)
    for pkt in packets:
        flows[pkt_flow_key(pkt)].append((pkt, float(pkt.time)))
    return flows


def compute_flow_features(flow_pkts):
    pkts = [p for p, _ in flow_pkts]
    times = [t for _, t in flow_pkts]
    count = len(pkts)
    if count == 0:
        return None

    duration = max(times) - min(times) if len(times) > 1 else 0.000001
    lengths, hdr_lens = [], []
    src_pkts = dst_pkts = 0
    src = dst = None
    src_ports, dst_ports = set(), set()
    proto_num = None
    flags = dict(fin=0, syn=0, rst=0, psh=0, ack=0, ece=0, cwr=0, urg=0)

    for pkt, _ in flow_pkts:
        lengths.append(len(pkt))
        if IP in pkt:
            proto_num = pkt[IP].proto
            ihl = getattr(pkt[IP], "ihl", None)
            if ihl:
                hdr_lens.append(ihl * 4)
            if src is None:
                src, dst = pkt[IP].src, pkt[IP].dst
            if pkt[IP].src == src:
                src_pkts += 1
            else:
                dst_pkts += 1
        if TCP in pkt:
            f = int(pkt[TCP].flags)
            if f & TCP_FIN: flags["fin"] += 1
            if f & TCP_SYN: flags["syn"] += 1
            if f & TCP_RST: flags["rst"] += 1
            if f & TCP_PSH: flags["psh"] += 1
            if f & TCP_ACK: flags["ack"] += 1
            if f & TCP_ECE: flags["ece"] += 1
            if f & TCP_CWR: flags["cwr"] += 1
            if f & TCP_URG: flags["urg"] += 1
            src_ports.add(pkt[TCP].sport); dst_ports.add(pkt[TCP].dport)
        elif UDP in pkt:
            src_ports.add(pkt[UDP].sport); dst_ports.add(pkt[UDP].dport)

    svc = {s: int(bool(src_ports & p or dst_ports & p)) for s, p in SERVICE_PORTS.items()}
    arr = np.array(lengths) if lengths else np.array([0])
    iat = float(np.mean(np.diff(sorted(times)))) if len(times) > 1 else 0.0

    return {
        "flow_duration": duration,
        "Header_Length": float(np.mean(hdr_lens)) if hdr_lens else 0.0,
        "Protocol Type": int(proto_num) if proto_num is not None else 0,
        "Duration": duration,
        "Rate": count / duration if duration > 0 else count,
        "Srate": src_pkts / duration if duration > 0 else 0,
        "Drate": dst_pkts / duration if duration > 0 else 0,
        "fin_flag_number": flags["fin"], "syn_flag_number": flags["syn"],
        "rst_flag_number": flags["rst"], "psh_flag_number": flags["psh"],
        "ack_flag_number": flags["ack"], "ece_flag_number": flags["ece"],
        "cwr_flag_number": flags["cwr"], "ack_count": flags["ack"],
        "syn_count": flags["syn"], "fin_count": flags["fin"],
        "urg_count": flags["urg"], "rst_count": flags["rst"],
        "HTTP": svc.get("HTTP", 0), "HTTPS": svc.get("HTTPS", 0),
        "DNS": svc.get("DNS", 0), "Telnet": svc.get("Telnet", 0),
        "SMTP": svc.get("SMTP", 0), "SSH": svc.get("SSH", 0),
        "IRC": svc.get("IRC", 0),
        "TCP": int(proto_num == 6), "UDP": int(proto_num == 17),
        "DHCP": svc.get("DHCP", 0),
        "ARP": int(any(ARP in p for p, _ in flow_pkts)),
        "ICMP": int(proto_num == 1), "IPv": int(proto_num is not None), "LLC": 0,
        "Tot sum": float(np.sum(arr)), "Min": float(np.min(arr)), "Max": float(np.max(arr)),
        "AVG": float(np.mean(arr)), "Std": float(np.std(arr)), "Tot size": float(np.sum(arr)),
        "IAT": iat, "Number": count,
        "Magnitue": float(np.sqrt(np.mean(arr ** 2))),
        "Radius": float(np.max(arr) - np.min(arr)),
        "Covariance": 0.0, "Variance": float(np.var(arr)),
        "Weight": float(np.sum(arr) / count) if count else 0.0,
    }


FEATURE_ORDER = [
    "flow_duration","Header_Length","Protocol Type","Duration","Rate","Srate","Drate",
    "fin_flag_number","syn_flag_number","rst_flag_number","psh_flag_number","ack_flag_number",
    "ece_flag_number","cwr_flag_number","ack_count","syn_count","fin_count","urg_count","rst_count",
    "HTTP","HTTPS","DNS","Telnet","SMTP","SSH","IRC","TCP","UDP","DHCP","ARP","ICMP","IPv","LLC",
    "Tot sum","Min","Max","AVG","Std","Tot size","IAT","Number","Magnitue","Radius","Covariance","Variance","Weight"
]


def flows_to_feature_matrix(flow_dict):
    features, metas = [], []
    for key, pkts in flow_dict.items():
        fd = compute_flow_features(pkts)
        if fd is None:
            continue
        features.append([float(fd.get(k, 0.0)) for k in FEATURE_ORDER])
        metas.append(key)
    return features, metas


def capture_and_extract_for_ip(ip, duration=10, iface=None, pcap_file=None):
    pkts = capture_packets_filtered(
        duration=duration, iface=iface,
        filter_expr=f"host {ip}", pcap_file=pcap_file
    )
    if not pkts:
        return [], []
    return flows_to_feature_matrix(group_packets_to_flows(pkts))


if __name__ == "__main__":
    iface = pick_best_interface()
    print(f"[*] Test capture on {iface}")
    pkts = sniff(timeout=5, iface=iface)
    print(f"[*] Got {len(pkts)} packets")