# app.py - Accurate version (no dummy data, correct device naming)
from flask import Flask, jsonify, render_template
import pickle, os, time, numpy as np, traceback, socket
from scanner import discover_devices, get_vendor_from_mac
from feature_extractor import capture_and_extract_for_ip

app = Flask(__name__, template_folder="templates")

MODEL_PATH = "iot_scanner_model.pkl"
CAPTURE_DURATION = 10
CAPTURE_INTERFACE = None   # auto-detect
PCAP_FALLBACK = None

# ---- Load model ----
model = None
model_loaded = False
if os.path.exists(MODEL_PATH):
    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        model_loaded = hasattr(model, "predict")
        print(f"[+] Model loaded: {type(model)}, has predict: {model_loaded}")
    except Exception as e:
        print(f"[!] Model load error: {e}")
else:
    print(f"[!] No model at {MODEL_PATH} — using port-based analysis only")


def local_network_cidr():
    """Compute the real local /24 CIDR."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ".".join(ip.split(".")[:3]) + ".0/24"
    except Exception:
        return "unknown"


@app.route("/")
def home():
    return render_template("UI.html")


@app.route("/scan_predict", methods=["GET"])
def scan_predict():
    try:
        net_cidr = local_network_cidr()
        print(f"[*] Scanning {net_cidr}")

        devices = discover_devices(scan_ports=True, port_scan_type="quick")

        if not devices:
            return jsonify({
                "predictions": [],
                "message": f"No devices discovered on {net_cidr}",
                "network_scanned": net_cidr,
            })

        results = []
        for dev in devices:
            ip = dev["ip"]
            hostname = dev.get("hostname", "Unknown")
            mac = dev.get("mac", "Unknown")
            device_type = dev.get("type", "Unknown")
            open_ports = dev.get("ports", [])
            vendor = dev.get("vendor")

            # ============================================================
            # FIXED NAMING: trust scanner's pre-computed name first
            # ============================================================
            device_name = (
                dev.get("name")
                or (hostname if hostname not in ("Unknown", "", ip) else None)
                or (f"{vendor} Device" if vendor else None)
                or (f"{device_type} ({ip})" if device_type and device_type != "Unknown" else None)
                or f"Device {ip}"
            )

            # Try ML flow analysis; fall back to port-based
            flow_results = []
            packet_count = 0

            if model_loaded:
                try:
                    features, metas = capture_and_extract_for_ip(
                        ip, duration=CAPTURE_DURATION,
                        iface=CAPTURE_INTERFACE, pcap_file=PCAP_FALLBACK
                    )
                    if features:
                        X = np.array(features)
                        preds = model.predict(X)
                        packet_count = len(features)
                        for meta, pred in zip(metas, preds):
                            src, dst, sport, dport, proto = meta
                            flow_results.append({
                                "flow": f"{src}:{sport}->{dst}:{dport}",
                                "src": src, "dst": dst,
                                "sport": sport, "dport": dport,
                                "protocol": proto,
                                "risk": int(pred),
                                "risk_level": get_risk_level(int(pred)),
                            })
                except Exception as e:
                    print(f"[!] Capture/ML failed for {ip}: {e}")

            if not flow_results:
                flow_results = port_based_analysis(ip, open_ports)

            overall = overall_risk(flow_results, device_type)

            results.append({
                "ip": ip,
                "name": device_name,
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "type": device_type,
                "ports": open_ports,
                "predictions": flow_results,
                "packet_count": packet_count,
                "overall_risk": overall,
                "risk_level": get_risk_level(overall),
                "status": "Online",
            })

        return jsonify({
            "predictions": results,
            "total_devices": len(results),
            "timestamp": time.time(),
            "network_scanned": net_cidr,
            "model_used": "ml_model" if model_loaded else "port_analysis",
        })

    except Exception as e:
        print("[!] scan_predict error:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500


def port_based_analysis(ip, open_ports):
    """Risk based solely on real open ports (no fabrication)."""
    SERVICE_RISK = {
        23: ("Telnet", 5), 21: ("FTP", 4), 161: ("SNMP", 4),
        162: ("SNMP-Trap", 4), 135: ("Windows RPC", 4), 445: ("SMB", 4),
        3389: ("RDP", 4), 139: ("NetBIOS", 3), 22: ("SSH", 3),
        554: ("RTSP", 3), 3306: ("MySQL", 3), 5432: ("PostgreSQL", 3),
        1433: ("MSSQL", 4), 80: ("HTTP", 2), 8080: ("HTTP-Alt", 2),
        8000: ("HTTP-Alt", 2), 8888: ("HTTP-Alt", 2), 5000: ("UPnP", 2),
        1900: ("SSDP", 2), 1883: ("MQTT", 2), 443: ("HTTPS", 1),
        53: ("DNS", 1), 67: ("DHCP", 1), 68: ("DHCP", 1),
        62078: ("iOS Sync", 1), 5353: ("mDNS", 1), 7000: ("AirPlay", 1),
        9100: ("Print", 2), 515: ("LPD", 2),
    }
    out = []
    for port in open_ports:
        name, risk = SERVICE_RISK.get(port, (f"Port-{port}", 2))
        out.append({
            "flow": f"{ip}:{port} ({name})",
            "src": ip, "dst": "network",
            "sport": port, "dport": "n/a",
            "protocol": "TCP",
            "risk": risk,
            "risk_level": get_risk_level(risk),
            "service": name,
        })
    return out


def overall_risk(flow_results, device_type):
    if not flow_results:
        return 1
    risks = [f["risk"] for f in flow_results]
    avg = sum(risks) / len(risks)
    if device_type and any(k in device_type for k in ("Mobile", "Phone", "iPhone")):
        avg -= 0.5
    return max(1, min(5, int(round(avg))))


def get_risk_level(score):
    return {1: "Very Low", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}.get(score, "Low")


@app.route("/network_info")
def network_info():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return jsonify({
            "local_ip": local_ip,
            "hostname": hostname,
            "target_network": local_network_cidr(),
            "model_loaded": model_loaded,
            "capture_interface": CAPTURE_INTERFACE,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/demo_scan")
def demo_scan():
    """Explicitly labeled DEMO data — only used when user clicks Demo tab."""
    demo = [
        {"ip": "192.168.1.4", "name": "Samsung Galaxy (Demo)", "type": "Mobile Device",
         "mac": "3C:5A:37:AA:BB:01", "ports": [80, 443], "overall_risk": 1,
         "risk_level": "Very Low", "status": "Demo",
         "predictions": [{"flow": "192.168.1.4:443 (HTTPS)", "risk": 1,
                          "risk_level": "Very Low", "service": "HTTPS"}]},
        {"ip": "192.168.1.10", "name": "Apple iPhone / iPad (Demo)", "type": "Mobile Device",
         "mac": "F0:18:98:AA:BB:02", "ports": [443, 62078], "overall_risk": 1,
         "risk_level": "Very Low", "status": "Demo",
         "predictions": [{"flow": "192.168.1.10:443 (HTTPS)", "risk": 1,
                          "risk_level": "Very Low", "service": "HTTPS"}]},
        {"ip": "192.168.1.78", "name": "IP Camera (Demo)", "type": "Camera",
         "mac": "B4:E6:2D:AA:BB:03", "ports": [80, 554, 8080], "overall_risk": 4,
         "risk_level": "High", "status": "Demo",
         "predictions": [{"flow": "192.168.1.78:554 (RTSP)", "risk": 4,
                          "risk_level": "High", "service": "RTSP"}]},
    ]
    return jsonify({
        "predictions": demo,
        "total_devices": len(demo),
        "timestamp": time.time(),
        "network_scanned": "DEMO",
        "model_used": "demo",
    })


if __name__ == "__main__":
    print("=" * 60)
    print("  MalScan - Real Network Mode")
    print("=" * 60)
    print(f"  Local CIDR : {local_network_cidr()}")
    print(f"  Model      : {'loaded' if model_loaded else 'not found'}")
    print(f"  Interface  : {CAPTURE_INTERFACE or 'auto-detect'}")
    print("  URL        : http://localhost:5321")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5321, debug=True)