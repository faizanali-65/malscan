# feature_extractor.py (fixed & improved)
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ARP, ICMP, get_if_list, conf
import numpy as np
from collections import defaultdict
import time
import os
# insert near top of your feature_extractor.py
from scapy.all import ARP, Ether, srp

def try_iface_list():
    """Return candidate ifaces (NPF GUIDs)."""
    return get_if_list()

def stimulate_device(ip, iface):
    """Send ARP who-has to the target to create traffic."""
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        srp(pkt, timeout=2, iface=iface, verbose=False)
        # small pause
        time.sleep(0.5)
    except Exception as e:
        print("[!] Stimulate failed:", e)



# -------- Service ports mapping --------
SERVICE_PORTS = {
    "HTTP": {80},
    "HTTPS": {443},
    "DNS": {53},
    "Telnet": {23},
    "SMTP": {25},
    "SSH": {22},
    "IRC": {194},
    "DHCP": {67, 68},
    "FTP": {20, 21},
}

# -------- TCP flag constants --------
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20
TCP_FLAG_ECE = 0x40
TCP_FLAG_CWR = 0x80


# -------- Utility: pick default interface --------
def get_default_iface():
    """Force use of the active Wi-Fi interface."""
    interfaces = get_if_list()
    target = "\\Device\\NPF_{BBF7B3CF-6B74-4407-BEA1-AD15A298585A}"  # your active Wi-Fi
    if target in interfaces:
        print(f"[*] Using fixed interface: {target}")
        return target
    print("[!] Fixed Wi-Fi interface not found, falling back to first interface.")
    return interfaces[0] if interfaces else None


# -------- Flow key generator --------
def pkt_flow_key(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
    else:
        src, dst, proto = "unknown", "unknown", 0

    sport, dport = None, None
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport

    return (src, dst, sport, dport, proto)


# -------- Packet capture --------
def capture_packets_filtered(duration=10, iface=None, filter_expr=None, pcap_file=None):
    if pcap_file:
        print("[*] Loading pcap:", pcap_file)
        return rdpcap(pcap_file)

    # If iface not provided, try conf.iface first then auto-select heuristic
    if iface is None:
        try:
            iface = conf.iface  # scapy's default iface guess
            print("[*] Scapy default iface:", iface)
        except Exception:
            iface = None

    if iface is None:
        iface = get_default_iface()

    # Stimulate the host (ARP ping) so it generates traffic to capture
    if filter_expr and filter_expr.startswith("host "):
        target_ip = filter_expr.split(" ", 1)[1]
        print(f"[*] Stimulating {target_ip} on iface {iface} to create traffic")
        stimulate_device(target_ip, iface)

    try:
        print(f"[*] Sniffing on {iface} for {duration}s with filter={filter_expr}")
        packets = sniff(timeout=duration, iface=iface, filter=filter_expr)
        print(f"[*] Captured {len(packets)} packets")
        # if zero, try one more time (shorter)
        if len(packets) == 0:
            print("[*] Zero packets — trying one more capture after stimulating again")
            if filter_expr and filter_expr.startswith("host "):
                stimulate_device(target_ip, iface)
            packets = sniff(timeout=max(3, duration//2), iface=iface, filter=filter_expr)
            print(f"[*] After retry captured {len(packets)} packets")
        return packets
    except PermissionError:
        print("❌ Permission denied. Run as Administrator (Windows) or sudo (Linux).")
        return []
    except Exception as e:
        print(f"❌ Sniff failed: {e}")
        return []



# -------- Grouping & feature extraction --------
def group_packets_to_flows(packets):
    flows = defaultdict(list)
    for pkt in packets:
        ts = float(pkt.time)
        key = pkt_flow_key(pkt)
        flows[key].append((pkt, ts))
    return flows


def compute_flow_features(flow_pkts):
    pkts = [p for (p, t) in flow_pkts]
    times = [t for (p, t) in flow_pkts]
    count = len(pkts)
    if count == 0:
        return None

    first_ts, last_ts = min(times), max(times)
    duration = last_ts - first_ts if last_ts > first_ts else 0.000001

    lengths, header_lengths = [], []
    src_pkt_count = dst_pkt_count = 0
    src = dst = None
    src_ports, dst_ports = set(), set()
    proto_num = None

    # TCP flag counters
    fin_flag_number = syn_flag_number = rst_flag_number = psh_flag_number = 0
    ack_flag_number = ece_flag_number = cwr_flag_number = urg_flag_number = 0

    for (pkt, ts) in flow_pkts:
        lengths.append(len(pkt))
        if IP in pkt:
            proto_num = pkt[IP].proto
            ihl = getattr(pkt[IP], "ihl", None)
            if ihl is not None:
                header_lengths.append(ihl * 4)
            if src is None:
                src, dst = pkt[IP].src, pkt[IP].dst
            if pkt[IP].src == src:
                src_pkt_count += 1
            else:
                dst_pkt_count += 1
        if TCP in pkt:
            flags = int(pkt[TCP].flags)
            if flags & TCP_FLAG_FIN: fin_flag_number += 1
            if flags & TCP_FLAG_SYN: syn_flag_number += 1
            if flags & TCP_FLAG_RST: rst_flag_number += 1
            if flags & TCP_FLAG_PSH: psh_flag_number += 1
            if flags & TCP_FLAG_ACK: ack_flag_number += 1
            if flags & TCP_FLAG_ECE: ece_flag_number += 1
            if flags & TCP_FLAG_CWR: cwr_flag_number += 1
            if flags & TCP_FLAG_URG: urg_flag_number += 1
            src_ports.add(pkt[TCP].sport)
            dst_ports.add(pkt[TCP].dport)
        elif UDP in pkt:
            src_ports.add(pkt[UDP].sport)
            dst_ports.add(pkt[UDP].dport)

    # Services
    service_presence = {svc: int(bool(src_ports & ports or dst_ports & ports))
                        for svc, ports in SERVICE_PORTS.items()}

    is_tcp = int(proto_num == 6)
    is_udp = int(proto_num == 17)
    is_icmp = int(proto_num == 1)
    is_arp = int(any(ARP in p for p, t in flow_pkts))
    is_dhcp = service_presence.get("DHCP", 0)
    is_ipv = int(proto_num is not None)

    lengths_arr = np.array(lengths) if lengths else np.array([0])
    tot_sum, minimum, maximum = np.sum(lengths_arr), np.min(lengths_arr), np.max(lengths_arr)
    avg, std, variance = np.mean(lengths_arr), np.std(lengths_arr), np.var(lengths_arr)
    number = count
    rate = number / duration if duration > 0 else number
    srate, drate = src_pkt_count / duration, dst_pkt_count / duration
    iat = np.mean(np.diff(sorted(times))) if len(times) > 1 else 0.0
    magnitude = float(np.sqrt(np.mean(lengths_arr ** 2)))
    radius = maximum - minimum
    cov = 0.0
    try:
        if len(times) > 1:
            iats = np.diff(sorted(times))
            minlen = min(len(iats), len(lengths_arr))
            cov = float(np.cov(lengths_arr[:minlen], iats[:minlen])[0, 1]) if minlen >= 1 else 0.0
    except Exception:
        cov = 0.0
    weight = tot_sum / number if number > 0 else 0.0

    return {
        "flow_duration": duration,
        "Header_Length": float(np.mean(header_lengths)) if header_lengths else 0.0,
        "Protocol Type": int(proto_num) if proto_num is not None else 0,
        "Duration": duration,
        "Rate": rate, "Srate": srate, "Drate": drate,
        "fin_flag_number": fin_flag_number, "syn_flag_number": syn_flag_number,
        "rst_flag_number": rst_flag_number, "psh_flag_number": psh_flag_number,
        "ack_flag_number": ack_flag_number, "ece_flag_number": ece_flag_number,
        "cwr_flag_number": cwr_flag_number, "ack_count": ack_flag_number,
        "syn_count": syn_flag_number, "fin_count": fin_flag_number,
        "urg_count": urg_flag_number, "rst_count": rst_flag_number,
        "HTTP": service_presence.get("HTTP", 0),
        "HTTPS": service_presence.get("HTTPS", 0),
        "DNS": service_presence.get("DNS", 0),
        "Telnet": service_presence.get("Telnet", 0),
        "SMTP": service_presence.get("SMTP", 0),
        "SSH": service_presence.get("SSH", 0),
        "IRC": service_presence.get("IRC", 0),
        "TCP": is_tcp, "UDP": is_udp, "DHCP": is_dhcp,
        "ARP": is_arp, "ICMP": is_icmp, "IPv": is_ipv, "LLC": 0,
        "Tot sum": tot_sum, "Min": minimum, "Max": maximum,
        "AVG": avg, "Std": std, "Tot size": tot_sum,
        "IAT": iat, "Number": number, "Magnitue": magnitude,
        "Radius": radius, "Covariance": cov, "Variance": variance, "Weight": weight
    }


def flows_to_feature_matrix(flow_dict):
    order = [
        "flow_duration","Header_Length","Protocol Type","Duration","Rate","Srate","Drate",
        "fin_flag_number","syn_flag_number","rst_flag_number","psh_flag_number","ack_flag_number",
        "ece_flag_number","cwr_flag_number","ack_count","syn_count","fin_count","urg_count","rst_count",
        "HTTP","HTTPS","DNS","Telnet","SMTP","SSH","IRC","TCP","UDP","DHCP","ARP","ICMP","IPv","LLC",
        "Tot sum","Min","Max","AVG","Std","Tot size","IAT","Number","Magnitue","Radius","Covariance","Variance","Weight"
    ]
    features, metas = [], []
    for key, pkts in flow_dict.items():
        featdict = compute_flow_features(pkts)
        if featdict is None:
            continue
        vec = [float(featdict.get(k, 0.0)) for k in order]
        features.append(vec)
        metas.append(key)
    return features, metas


def capture_and_extract_for_ip(ip, duration=10, iface=None, pcap_file=None):
    filter_expr = f"host {ip}"
    pkts = capture_packets_filtered(duration=duration, iface=iface, filter_expr=filter_expr, pcap_file=pcap_file)
    if not pkts or len(pkts) == 0:
        return [], []
    flows = group_packets_to_flows(pkts)
    return flows_to_feature_matrix(flows)


# -------- Debug run --------
if __name__ == "__main__":
    print("[*] Running feature_extractor debug mode...")
    iface = get_default_iface()
    pkts = sniff(timeout=5, iface=iface)
    print(f"[*] Test capture got {len(pkts)} packets")
    if pkts:
        print(pkts.summary())
