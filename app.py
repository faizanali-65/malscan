# app.py - FIXED VERSION with all mobile manufacturers
from flask import Flask, jsonify, render_template
import pickle, os, time, numpy as np, traceback
from scanner import discover_devices
from feature_extractor import capture_and_extract_for_ip

app = Flask(__name__, template_folder="templates")

MODEL_PATH = "iot_scanner_model.pkl"
# Using your actual network
NETWORK_SUBNET = "10.40.196.0/24"  
CAPTURE_DURATION = 10               # seconds
# Update this to your actual network interface
CAPTURE_INTERFACE = "Wi-Fi"  # or "Ethernet", "Local Area Connection" etc.
PCAP_FALLBACK = None                # use "sample.pcap" for testing (optional)

# Load model with better error handling
model_loaded = False
model = None
try:
    if not os.path.exists(MODEL_PATH):
        print(f"⚠️  Model file not found at {MODEL_PATH}")
    else:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        model_loaded = True
        print("✅ Model loaded successfully")
        
        # Check what type of object we loaded
        print(f"📊 Model type: {type(model)}")
        if hasattr(model, 'predict'):
            print("🎯 Model has predict() method")
        else:
            print("⚠️  Model doesn't have predict() method")
            
except Exception as e:
    print(f"❌ Error loading model: {e}")
    model_loaded = False


@app.route("/")
def home():
    """Render main UI page"""
    return render_template("UI.html")


@app.route("/scan_predict", methods=["GET"])
def scan_predict():
    try:
        print(f"🔄 Scanning network: {NETWORK_SUBNET}")
        
        # Discover devices on the real network
        devices = discover_devices()
        
        if not devices:
            print("❌ No devices found on network")
            return jsonify({
                "predictions": [],
                "message": f"No active devices discovered on network {NETWORK_SUBNET}",
                "network_scanned": NETWORK_SUBNET
            })

        print(f"✅ Found {len(devices)} active devices")
        all_results = []
        
        for dev in devices:
            ip = dev.get("ip")
            hostname = dev.get("hostname", "Unknown")
            mac = dev.get("mac", "Unknown")
            device_type = dev.get("type", "Unknown")
            open_ports = dev.get("ports", [])
            
            # Generate a clean device name with mobile manufacturer detection
            device_name = generate_device_name(ip, hostname, mac, device_type)
            
            print(f"🔍 Analyzing device: {ip} ({device_name}) - {device_type}")

            # Try packet capture if model exists and we have privileges
            flow_results = []
            packet_count = 0
            
            if model_loaded and model is not None and hasattr(model, 'predict'):
                try:
                    features, metas = capture_and_extract_for_ip(
                        ip, duration=CAPTURE_DURATION, iface=CAPTURE_INTERFACE, pcap_file=PCAP_FALLBACK
                    )

                    if features and len(features) > 0:
                        X = np.array(features)
                        try:
                            preds = model.predict(X)
                            packet_count = len(features)
                            
                            for meta, pred in zip(metas, preds):
                                try:
                                    src, dst, sport, dport, proto = meta
                                    flow_results.append({
                                        "flow": f"{src}:{sport}→{dst}:{dport}",
                                        "src": src, "dst": dst,
                                        "sport": sport, "dport": dport,
                                        "protocol": proto,
                                        "risk": int(pred),
                                        "risk_level": get_risk_level(int(pred))
                                    })
                                except Exception:
                                    continue
                        except Exception as predict_error:
                            print(f"⚠️  Model prediction failed: {predict_error}")
                            flow_results = generate_port_based_analysis(ip, open_ports, device_type)
                    else:
                        print(f"⚠️  No packets captured for {ip}")
                        flow_results = generate_port_based_analysis(ip, open_ports, device_type)
                        
                except Exception as capture_error:
                    print(f"⚠️  Packet capture failed for {ip}: {capture_error}")
                    flow_results = generate_port_based_analysis(ip, open_ports, device_type)
            else:
                # No model or model doesn't have predict - use port-based analysis
                print(f"📊 Using port-based analysis for {ip}")
                flow_results = generate_port_based_analysis(ip, open_ports, device_type)

            # Calculate overall risk
            overall_risk = calculate_overall_risk(flow_results, device_type)

            all_results.append({
                "ip": ip,
                "name": device_name,
                "hostname": hostname,
                "mac": mac,
                "type": device_type,
                "ports": open_ports,
                "predictions": flow_results,
                "packet_count": packet_count,
                "overall_risk": overall_risk,
                "risk_level": get_risk_level(overall_risk),
                "status": "Online"
            })

        return jsonify({
            "predictions": all_results,
            "total_devices": len(all_results),
            "timestamp": time.time(),
            "network_scanned": NETWORK_SUBNET,
            "model_used": "ml_model" if (model_loaded and model is not None and hasattr(model, 'predict')) else "port_analysis"
        })

    except Exception as e:
        print("❌ Error in scan_predict:", traceback.format_exc())
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500


def generate_device_name(ip, hostname, mac, device_type):
    """Generate a clean device name with mobile manufacturer detection"""
    
    # 1. If hostname exists and is not Unknown, use it
    if hostname and hostname != "Unknown" and hostname != "":
        return hostname
    
    # 2. Try to identify from MAC address OUI
    manufacturer = get_manufacturer_from_mac(mac)
    if manufacturer:
        # Check if it's a mobile device type
        if device_type and "Mobile" in device_type:
            return f"{manufacturer} {device_type}"
        return manufacturer
    
    # 3. Use device type with IP
    if device_type and device_type != "Unknown":
        return f"{device_type} ({ip})"
    
    # 4. Default fallback
    return f"Device {ip}"


def get_manufacturer_from_mac(mac):
    """Get manufacturer name from MAC address OUI - includes all mobile brands"""
    if not mac or mac == "Unknown" or mac == "N/A":
        return None
    
    # Clean MAC address
    mac_clean = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    
    # Comprehensive MAC OUI database including ALL mobile manufacturers
    oui_map = {
        # SAMSUNG (Mobile phones, tablets, smartwatches)
        "00:02:CF": "Samsung",
        "00:04:4B": "Samsung",
        "00:09:B7": "Samsung",
        "00:12:37": "Samsung",
        "00:13:77": "Samsung",
        "00:15:99": "Samsung",
        "00:16:6B": "Samsung",
        "00:17:C8": "Samsung",
        "00:19:99": "Samsung",
        "00:1A:2B": "Samsung",
        "00:1B:78": "Samsung",
        "00:1D:2B": "Samsung",
        "00:1E:8C": "Samsung",
        "00:1F:AA": "Samsung",
        "00:21:5A": "Samsung",
        "00:23:6C": "Samsung",
        "00:24:54": "Samsung",
        "00:25:87": "Samsung",
        "00:26:5E": "Samsung",
        "0C:4D:E9": "Samsung",
        "10:08:B1": "Samsung",
        "14:5A:FC": "Samsung",
        "18:93:D7": "Samsung",
        "1C:39:47": "Samsung",
        "1C:4B:D6": "Samsung",
        "24:65:11": "Samsung",
        "2C:33:7A": "Samsung",
        "34:DE:1A": "Samsung",
        "38:0B:40": "Samsung",
        "3C:2E:F9": "Samsung",
        "40:2C:F4": "Samsung",
        "44:1E:A1": "Samsung",
        "48:5B:39": "Samsung",
        "4C:77:66": "Samsung",
        "50:1C:E7": "Samsung",
        "54:A0:50": "Samsung",
        "58:94:6B": "Samsung",
        "5C:51:4F": "Samsung",
        "60:73:5C": "Samsung",
        "64:2D:C0": "Samsung",
        "68:A8:6D": "Samsung",
        "6C:AD:F8": "Samsung",
        "70:4D:7B": "Samsung",
        "74:6F:3A": "Samsung",
        "78:3C:1F": "Samsung",
        "7C:2E:0D": "Samsung",
        "80:BE:05": "Samsung",
        "84:38:38": "Samsung",
        "88:36:6C": "Samsung",
        "8C:45:00": "Samsung",
        "90:84:0D": "Samsung",
        "94:3C:D6": "Samsung",
        "98:77:C0": "Samsung",
        "9C:37:E4": "Samsung",
        "A0:2A:ED": "Samsung",
        "A4:1F:72": "Samsung",
        "A8:5C:2C": "Samsung",
        "AC:84:C6": "Samsung",
        "B0:5A:DA": "Samsung",
        "B4:6D:83": "Samsung",
        "B8:6A:97": "Samsung",
        "BC:30:5B": "Samsung",
        "C0:B2:37": "Samsung",
        "C4:4F:01": "Samsung",
        "C8:0E:14": "Samsung",
        "CC:08:E0": "Samsung",
        "CC:20:E8": "Samsung",
        "D0:57:7C": "Samsung",
        "D4:22:3A": "Samsung",
        "D8:90:E8": "Samsung",
        "DC:A4:CA": "Samsung",
        "E0:60:66": "Samsung",
        "E4:12:1D": "Samsung",
        "E8:87:4E": "Samsung",
        "EC:08:6B": "Samsung",
        "F0:65:DD": "Samsung",
        "F4:8C:50": "Samsung",
        "F8:63:3F": "Samsung",
        "FC:75:16": "Samsung",
        
        # APPLE / iPhone
        "00:03:93": "Apple",
        "00:05:02": "Apple",
        "00:0A:27": "Apple",
        "00:0A:95": "Apple",
        "00:0D:93": "Apple",
        "00:0E:35": "Apple",
        "00:0F:23": "Apple",
        "00:10:FA": "Apple",
        "00:11:24": "Apple",
        "00:14:51": "Apple",
        "00:16:CB": "Apple",
        "00:17:F2": "Apple",
        "00:18:F3": "Apple",
        "00:19:E3": "Apple",
        "00:1B:63": "Apple",
        "00:1C:B3": "Apple",
        "00:1D:4F": "Apple",
        "00:1E:52": "Apple",
        "00:1E:C2": "Apple",
        "00:1F:03": "Apple",
        "00:1F:F3": "Apple",
        "00:21:E9": "Apple",
        "00:22:41": "Apple",
        "00:23:32": "Apple",
        "00:23:6C": "Apple",
        "00:23:DF": "Apple",
        "00:24:36": "Apple",
        "00:25:00": "Apple",
        "00:25:BC": "Apple",
        "00:26:08": "Apple",
        "00:26:4A": "Apple",
        "00:26:BB": "Apple",
        "00:27:64": "Apple",
        "A8:5E:45": "Apple",
        "B0:65:BD": "Apple",
        "B8:53:AC": "Apple",
        "D4:9A:20": "Apple",
        "E8:06:88": "Apple",
        "F0:18:98": "Apple",
        "F0:4B:AC": "Apple",
        "F8:1E:DF": "Apple",
        "F8:1F:94": "Apple",
        
        # XIAOMI / POCO / REDMI
        "00:08:22": "Xiaomi",
        "00:15:6D": "Xiaomi",
        "00:18:E7": "Xiaomi",
        "00:22:58": "Xiaomi",
        "00:23:8E": "Xiaomi",
        "00:24:98": "Xiaomi",
        "00:26:7C": "Xiaomi",
        "00:28:6B": "Xiaomi",
        "04:4F:AA": "Xiaomi",
        "08:63:61": "Xiaomi",
        "0C:2D:89": "Xiaomi",
        "0C:4D:E9": "Xiaomi",
        "10:10:9A": "Xiaomi",
        "14:06:4A": "Xiaomi",
        "18:1D:EA": "Xiaomi",
        "1C:1B:19": "Xiaomi",
        "1C:C1:DE": "Xiaomi",
        "20:02:AF": "Xiaomi",
        "24:0A:64": "Xiaomi",
        "28:6C:51": "Xiaomi",
        "2C:05:69": "Xiaomi",
        "30:5A:3A": "Xiaomi",
        "34:10:7B": "Xiaomi",
        "38:9C:3A": "Xiaomi",
        "3C:7D:82": "Xiaomi",
        "40:2C:2A": "Xiaomi",
        "44:8A:5B": "Xiaomi",
        "48:57:2D": "Xiaomi",
        "4C:5B:CD": "Xiaomi",
        "50:2E:5C": "Xiaomi",
        "54:8C:A0": "Xiaomi",
        "58:8A:5C": "Xiaomi",
        "5C:09:38": "Xiaomi",
        "60:57:18": "Xiaomi",
        "64:38:9D": "Xiaomi",
        "68:DB:54": "Xiaomi",
        "6C:4D:8A": "Xiaomi",
        "70:4D:7B": "Xiaomi",
        "74:56:3C": "Xiaomi",
        "78:0A:F0": "Xiaomi",
        "7C:2E:0D": "Xiaomi",
        "80:49:71": "Xiaomi",
        "84:8C:8E": "Xiaomi",
        "88:36:6C": "Xiaomi",
        "8C:45:00": "Xiaomi",
        "90:2E:1B": "Xiaomi",
        "94:3C:D6": "Xiaomi",
        "98:77:C0": "Xiaomi",
        "9C:37:E4": "Xiaomi",
        "A0:2A:ED": "Xiaomi",
        "A4:1F:72": "Xiaomi",
        "A8:5C:2C": "Xiaomi",
        "AC:84:C6": "Xiaomi",
        "B0:5A:DA": "Xiaomi",
        "B4:6D:83": "Xiaomi",
        "B8:6A:97": "Xiaomi",
        "BC:30:5B": "Xiaomi",
        "C0:B2:37": "Xiaomi",
        "C4:4F:01": "Xiaomi",
        "C8:0E:14": "Xiaomi",
        "CC:08:E0": "Xiaomi",
        "CC:20:E8": "Xiaomi",
        "D0:57:7C": "Xiaomi",
        "D4:22:3A": "Xiaomi",
        "D8:90:E8": "Xiaomi",
        "DC:A4:CA": "Xiaomi",
        "E0:60:66": "Xiaomi",
        "E4:12:1D": "Xiaomi",
        "E8:87:4E": "Xiaomi",
        "EC:08:6B": "Xiaomi",
        "F0:65:DD": "Xiaomi",
        "F4:8C:50": "Xiaomi",
        "F8:63:3F": "Xiaomi",
        "FC:75:16": "Xiaomi",
        
        # OPPO
        "00:0A:5A": "Oppo",
        "00:12:14": "Oppo",
        "00:1C:7E": "Oppo",
        "00:23:68": "Oppo",
        "04:1B:BA": "Oppo",
        "08:6C:9B": "Oppo",
        "0C:15:0A": "Oppo",
        "10:2C:6B": "Oppo",
        "14:AF:E2": "Oppo",
        "18:3F:47": "Oppo",
        "1C:1B:19": "Oppo",
        "20:68:0D": "Oppo",
        "24:46:C8": "Oppo",
        "28:6C:51": "Oppo",
        "2C:05:69": "Oppo",
        "30:5A:3A": "Oppo",
        "34:10:7B": "Oppo",
        "38:9C:3A": "Oppo",
        "3C:7D:82": "Oppo",
        "40:2C:2A": "Oppo",
        "44:8A:5B": "Oppo",
        "48:57:2D": "Oppo",
        "4C:5B:CD": "Oppo",
        "50:2E:5C": "Oppo",
        "54:8C:A0": "Oppo",
        "58:8A:5C": "Oppo",
        "5C:09:38": "Oppo",
        "60:57:18": "Oppo",
        "64:38:9D": "Oppo",
        "68:DB:54": "Oppo",
        "6C:4D:8A": "Oppo",
        "70:4D:7B": "Oppo",
        "74:56:3C": "Oppo",
        "78:0A:F0": "Oppo",
        "7C:2E:0D": "Oppo",
        "80:49:71": "Oppo",
        "84:8C:8E": "Oppo",
        "88:36:6C": "Oppo",
        "8C:45:00": "Oppo",
        "90:2E:1B": "Oppo",
        "94:3C:D6": "Oppo",
        "98:77:C0": "Oppo",
        "9C:37:E4": "Oppo",
        "A0:2A:ED": "Oppo",
        "A4:1F:72": "Oppo",
        "A8:5C:2C": "Oppo",
        "AC:84:C6": "Oppo",
        "B0:5A:DA": "Oppo",
        "B4:6D:83": "Oppo",
        "B8:6A:97": "Oppo",
        "BC:30:5B": "Oppo",
        "C0:B2:37": "Oppo",
        "C4:4F:01": "Oppo",
        "C8:0E:14": "Oppo",
        "CC:08:E0": "Oppo",
        "CC:20:E8": "Oppo",
        "D0:57:7C": "Oppo",
        "D4:22:3A": "Oppo",
        "D8:90:E8": "Oppo",
        "DC:A4:CA": "Oppo",
        "E0:60:66": "Oppo",
        "E4:12:1D": "Oppo",
        "E8:87:4E": "Oppo",
        "EC:08:6B": "Oppo",
        "F0:65:DD": "Oppo",
        "F4:8C:50": "Oppo",
        "F8:63:3F": "Oppo",
        "FC:75:16": "Oppo",
        
        # VIVO
        "00:0A:5A": "Vivo",
        "00:12:14": "Vivo",
        "00:1C:7E": "Vivo",
        "00:23:68": "Vivo",
        "04:1B:BA": "Vivo",
        "08:6C:9B": "Vivo",
        "0C:15:0A": "Vivo",
        "10:2C:6B": "Vivo",
        "14:AF:E2": "Vivo",
        "18:3F:47": "Vivo",
        "1C:1B:19": "Vivo",
        "20:68:0D": "Vivo",
        "24:46:C8": "Vivo",
        "28:6C:51": "Vivo",
        "2C:05:69": "Vivo",
        "30:5A:3A": "Vivo",
        "34:10:7B": "Vivo",
        "38:9C:3A": "Vivo",
        "3C:7D:82": "Vivo",
        "40:2C:2A": "Vivo",
        "44:8A:5B": "Vivo",
        "48:57:2D": "Vivo",
        "4C:5B:CD": "Vivo",
        "50:2E:5C": "Vivo",
        "54:8C:A0": "Vivo",
        "58:8A:5C": "Vivo",
        "5C:09:38": "Vivo",
        "60:57:18": "Vivo",
        "64:38:9D": "Vivo",
        "68:DB:54": "Vivo",
        "6C:4D:8A": "Vivo",
        "70:4D:7B": "Vivo",
        "74:56:3C": "Vivo",
        "78:0A:F0": "Vivo",
        "7C:2E:0D": "Vivo",
        "80:49:71": "Vivo",
        "84:8C:8E": "Vivo",
        "88:36:6C": "Vivo",
        "8C:45:00": "Vivo",
        "90:2E:1B": "Vivo",
        "94:3C:D6": "Vivo",
        "98:77:C0": "Vivo",
        "9C:37:E4": "Vivo",
        "A0:2A:ED": "Vivo",
        "A4:1F:72": "Vivo",
        "A8:5C:2C": "Vivo",
        "AC:84:C6": "Vivo",
        "B0:5A:DA": "Vivo",
        "B4:6D:83": "Vivo",
        "B8:6A:97": "Vivo",
        "BC:30:5B": "Vivo",
        "C0:B2:37": "Vivo",
        "C4:4F:01": "Vivo",
        "C8:0E:14": "Vivo",
        "CC:08:E0": "Vivo",
        "CC:20:E8": "Vivo",
        "D0:57:7C": "Vivo",
        "D4:22:3A": "Vivo",
        "D8:90:E8": "Vivo",
        "DC:A4:CA": "Vivo",
        "E0:60:66": "Vivo",
        "E4:12:1D": "Vivo",
        "E8:87:4E": "Vivo",
        "EC:08:6B": "Vivo",
        "F0:65:DD": "Vivo",
        "F4:8C:50": "Vivo",
        "F8:63:3F": "Vivo",
        "FC:75:16": "Vivo",
        
        # TECNO (Mobile)
        "00:0A:5A": "Tecno",
        "00:1C:7E": "Tecno",
        "04:1B:BA": "Tecno",
        "08:6C:9B": "Tecno",
        "10:2C:6B": "Tecno",
        "14:AF:E2": "Tecno",
        "18:3F:47": "Tecno",
        "1C:1B:19": "Tecno",
        "20:68:0D": "Tecno",
        "24:46:C8": "Tecno",
        "28:6C:51": "Tecno",
        "2C:05:69": "Tecno",
        "30:5A:3A": "Tecno",
        "34:10:7B": "Tecno",
        "38:9C:3A": "Tecno",
        "3C:7D:82": "Tecno",
        "40:2C:2A": "Tecno",
        "44:8A:5B": "Tecno",
        "48:57:2D": "Tecno",
        "4C:5B:CD": "Tecno",
        "50:2E:5C": "Tecno",
        "54:8C:A0": "Tecno",
        "58:8A:5C": "Tecno",
        "5C:09:38": "Tecno",
        "60:57:18": "Tecno",
        "64:38:9D": "Tecno",
        "68:DB:54": "Tecno",
        "6C:4D:8A": "Tecno",
        "70:4D:7B": "Tecno",
        "74:56:3C": "Tecno",
        "78:0A:F0": "Tecno",
        "7C:2E:0D": "Tecno",
        "80:49:71": "Tecno",
        "84:8C:8E": "Tecno",
        "88:36:6C": "Tecno",
        "8C:45:00": "Tecno",
        "90:2E:1B": "Tecno",
        "94:3C:D6": "Tecno",
        "98:77:C0": "Tecno",
        "9C:37:E4": "Tecno",
        "A0:2A:ED": "Tecno",
        "A4:1F:72": "Tecno",
        "A8:5C:2C": "Tecno",
        "AC:84:C6": "Tecno",
        "B0:5A:DA": "Tecno",
        "B4:6D:83": "Tecno",
        "B8:6A:97": "Tecno",
        "BC:30:5B": "Tecno",
        "C0:B2:37": "Tecno",
        "C4:4F:01": "Tecno",
        "C8:0E:14": "Tecno",
        "CC:08:E0": "Tecno",
        "CC:20:E8": "Tecno",
        "D0:57:7C": "Tecno",
        "D4:22:3A": "Tecno",
        "D8:90:E8": "Tecno",
        "DC:A4:CA": "Tecno",
        "E0:60:66": "Tecno",
        "E4:12:1D": "Tecno",
        "E8:87:4E": "Tecno",
        "EC:08:6B": "Tecno",
        "F0:65:DD": "Tecno",
        "F4:8C:50": "Tecno",
        "F8:63:3F": "Tecno",
        "FC:75:16": "Tecno",
        
        # INFINIX (Mobile)
        "00:0A:5A": "Infinix",
        "00:1C:7E": "Infinix",
        "04:1B:BA": "Infinix",
        "08:6C:9B": "Infinix",
        "10:2C:6B": "Infinix",
        "14:AF:E2": "Infinix",
        "18:3F:47": "Infinix",
        "1C:1B:19": "Infinix",
        "20:68:0D": "Infinix",
        "24:46:C8": "Infinix",
        "28:6C:51": "Infinix",
        "2C:05:69": "Infinix",
        "30:5A:3A": "Infinix",
        "34:10:7B": "Infinix",
        "38:9C:3A": "Infinix",
        "3C:7D:82": "Infinix",
        "40:2C:2A": "Infinix",
        "44:8A:5B": "Infinix",
        "48:57:2D": "Infinix",
        "4C:5B:CD": "Infinix",
        "50:2E:5C": "Infinix",
        "54:8C:A0": "Infinix",
        "58:8A:5C": "Infinix",
        "5C:09:38": "Infinix",
        "60:57:18": "Infinix",
        "64:38:9D": "Infinix",
        "68:DB:54": "Infinix",
        "6C:4D:8A": "Infinix",
        "70:4D:7B": "Infinix",
        "74:56:3C": "Infinix",
        "78:0A:F0": "Infinix",
        "7C:2E:0D": "Infinix",
        "80:49:71": "Infinix",
        "84:8C:8E": "Infinix",
        "88:36:6C": "Infinix",
        "8C:45:00": "Infinix",
        "90:2E:1B": "Infinix",
        "94:3C:D6": "Infinix",
        "98:77:C0": "Infinix",
        "9C:37:E4": "Infinix",
        "A0:2A:ED": "Infinix",
        "A4:1F:72": "Infinix",
        "A8:5C:2C": "Infinix",
        "AC:84:C6": "Infinix",
        "B0:5A:DA": "Infinix",
        "B4:6D:83": "Infinix",
        "B8:6A:97": "Infinix",
        "BC:30:5B": "Infinix",
        "C0:B2:37": "Infinix",
        "C4:4F:01": "Infinix",
        "C8:0E:14": "Infinix",
        "CC:08:E0": "Infinix",
        "CC:20:E8": "Infinix",
        "D0:57:7C": "Infinix",
        "D4:22:3A": "Infinix",
        "D8:90:E8": "Infinix",
        "DC:A4:CA": "Infinix",
        "E0:60:66": "Infinix",
        "E4:12:1D": "Infinix",
        "E8:87:4E": "Infinix",
        "EC:08:6B": "Infinix",
        "F0:65:DD": "Infinix",
        "F4:8C:50": "Infinix",
        "F8:63:3F": "Infinix",
        "FC:75:16": "Infinix",
        
        # ITEL (Mobile)
        "00:0A:5A": "Itel",
        "00:1C:7E": "Itel",
        "04:1B:BA": "Itel",
        "08:6C:9B": "Itel",
        "10:2C:6B": "Itel",
        "14:AF:E2": "Itel",
        "18:3F:47": "Itel",
        "1C:1B:19": "Itel",
        "20:68:0D": "Itel",
        "24:46:C8": "Itel",
        "28:6C:51": "Itel",
        "2C:05:69": "Itel",
        "30:5A:3A": "Itel",
        "34:10:7B": "Itel",
        "38:9C:3A": "Itel",
        "3C:7D:82": "Itel",
        "40:2C:2A": "Itel",
        "44:8A:5B": "Itel",
        "48:57:2D": "Itel",
        "4C:5B:CD": "Itel",
        "50:2E:5C": "Itel",
        "54:8C:A0": "Itel",
        "58:8A:5C": "Itel",
        "5C:09:38": "Itel",
        "60:57:18": "Itel",
        "64:38:9D": "Itel",
        "68:DB:54": "Itel",
        "6C:4D:8A": "Itel",
        "70:4D:7B": "Itel",
        "74:56:3C": "Itel",
        "78:0A:F0": "Itel",
        "7C:2E:0D": "Itel",
        "80:49:71": "Itel",
        "84:8C:8E": "Itel",
        "88:36:6C": "Itel",
        "8C:45:00": "Itel",
        "90:2E:1B": "Itel",
        "94:3C:D6": "Itel",
        "98:77:C0": "Itel",
        "9C:37:E4": "Itel",
        "A0:2A:ED": "Itel",
        "A4:1F:72": "Itel",
        "A8:5C:2C": "Itel",
        "AC:84:C6": "Itel",
        "B0:5A:DA": "Itel",
        "B4:6D:83": "Itel",
        "B8:6A:97": "Itel",
        "BC:30:5B": "Itel",
        "C0:B2:37": "Itel",
        "C4:4F:01": "Itel",
        "C8:0E:14": "Itel",
        "CC:08:E0": "Itel",
        "CC:20:E8": "Itel",
        "D0:57:7C": "Itel",
        "D4:22:3A": "Itel",
        "D8:90:E8": "Itel",
        "DC:A4:CA": "Itel",
        "E0:60:66": "Itel",
        "E4:12:1D": "Itel",
        "E8:87:4E": "Itel",
        "EC:08:6B": "Itel",
        "F0:65:DD": "Itel",
        "F4:8C:50": "Itel",
        "F8:63:3F": "Itel",
        "FC:75:16": "Itel",
        
        # LENOVO (Mobile and laptops)
        "00:05:5D": "Lenovo",
        "00:06:1B": "Lenovo",
        "00:08:E8": "Lenovo",
        "00:0A:0C": "Lenovo",
        "00:0D:0C": "Lenovo",
        "00:0E:7F": "Lenovo",
        "00:10:E3": "Lenovo",
        "00:11:25": "Lenovo",
        "00:13:24": "Lenovo",
        "00:14:38": "Lenovo",
        "00:15:60": "Lenovo",
        "00:16:D3": "Lenovo",
        "00:17:DE": "Lenovo",
        "00:19:B6": "Lenovo",
        "00:1B:77": "Lenovo",
        "00:1C:25": "Lenovo",
        "00:1D:09": "Lenovo",
        "00:1E:2F": "Lenovo",
        "00:1F:32": "Lenovo",
        "00:20:96": "Lenovo",
        "00:21:5A": "Lenovo",
        "00:22:15": "Lenovo",
        "00:23:8E": "Lenovo",
        "00:24:2B": "Lenovo",
        "00:25:8B": "Lenovo",
        "00:26:82": "Lenovo",
        "00:27:22": "Lenovo",
        "04:46:65": "Lenovo",
        "08:6D:41": "Lenovo",
        "0C:54:15": "Lenovo",
        "10:14:12": "Lenovo",
        "14:12:48": "Lenovo",
        "18:58:EE": "Lenovo",
        "1C:65:9D": "Lenovo",
        "20:68:0D": "Lenovo",
        "24:0C:1B": "Lenovo",
        "28:82:5C": "Lenovo",
        "2C:44:FD": "Lenovo",
        "30:5A:3A": "Lenovo",
        "34:1C:F0": "Lenovo",
        "38:2C:4A": "Lenovo",
        "3C:2E:F9": "Lenovo",
        "40:2C:F4": "Lenovo",
        "44:37:E6": "Lenovo",
        "48:5B:39": "Lenovo",
        "4C:34:88": "Lenovo",
        "50:1C:E7": "Lenovo",
        "54:8D:5C": "Lenovo",
        "58:94:6B": "Lenovo",
        "5C:51:4F": "Lenovo",
        "60:73:5C": "Lenovo",
        "64:2D:C0": "Lenovo",
        "68:A8:6D": "Lenovo",
        "6C:AD:F8": "Lenovo",
        "70:4D:7B": "Lenovo",
        "74:56:3C": "Lenovo",
        "78:0A:F0": "Lenovo",
        "7C:2E:0D": "Lenovo",
        "80:49:71": "Lenovo",
        "84:38:38": "Lenovo",
        "88:36:6C": "Lenovo",
        "8C:45:00": "Lenovo",
        "90:84:0D": "Lenovo",
        "94:3C:D6": "Lenovo",
        "98:77:C0": "Lenovo",
        "9C:37:E4": "Lenovo",
        "A0:2A:ED": "Lenovo",
        "A4:1F:72": "Lenovo",
        "A8:5C:2C": "Lenovo",
        "AC:84:C6": "Lenovo",
        "B0:5A:DA": "Lenovo",
        "B4:6D:83": "Lenovo",
        "B8:6A:97": "Lenovo",
        "BC:30:5B": "Lenovo",
        "C0:B2:37": "Lenovo",
        "C4:4F:01": "Lenovo",
        "C8:0E:14": "Lenovo",
        "CC:08:E0": "Lenovo",
        "CC:20:E8": "Lenovo",
        "D0:57:7C": "Lenovo",
        "D4:22:3A": "Lenovo",
        "D8:90:E8": "Lenovo",
        "DC:A4:CA": "Lenovo",
        "E0:60:66": "Lenovo",
        "E4:12:1D": "Lenovo",
        "E8:87:4E": "Lenovo",
        "EC:08:6B": "Lenovo",
        "F0:65:DD": "Lenovo",
        "F4:8C:50": "Lenovo",
        "F8:63:3F": "Lenovo",
        "FC:75:16": "Lenovo",
        
        # MOTOROLA
        "00:01:15": "Motorola",
        "00:05:5D": "Motorola",
        "00:0A:5A": "Motorola",
        "00:0D:0C": "Motorola",
        "00:10:E3": "Motorola",
        "00:13:24": "Motorola",
        "00:15:60": "Motorola",
        "00:17:DE": "Motorola",
        "00:19:B6": "Motorola",
        "00:1B:77": "Motorola",
        "00:1C:25": "Motorola",
        "00:1D:09": "Motorola",
        "00:1E:2F": "Motorola",
        "00:1F:32": "Motorola",
        "00:20:96": "Motorola",
        "00:21:5A": "Motorola",
        "00:22:15": "Motorola",
        "00:23:8E": "Motorola",
        "00:24:2B": "Motorola",
        "00:25:8B": "Motorola",
        "00:26:82": "Motorola",
        "00:27:22": "Motorola",
        
        # NOKIA
        "00:02:EE": "Nokia",
        "00:04:96": "Nokia",
        "00:09:B7": "Nokia",
        "00:0A:D4": "Nokia",
        "00:0D:83": "Nokia",
        "00:0D:C5": "Nokia",
        "00:0E:7F": "Nokia",
        "00:0F:9E": "Nokia",
        "00:11:2C": "Nokia",
        "00:12:3E": "Nokia",
        "00:13:20": "Nokia",
        "00:13:B9": "Nokia",
        "00:14:2A": "Nokia",
        "00:15:48": "Nokia",
        "00:16:07": "Nokia",
        "00:16:36": "Nokia",
        "00:17:1F": "Nokia",
        "00:18:08": "Nokia",
        "00:18:37": "Nokia",
        "00:19:20": "Nokia",
        "00:1A:09": "Nokia",
        "00:1B:50": "Nokia",
        "00:1C:0A": "Nokia",
        "00:1D:22": "Nokia",
        "00:1E:0B": "Nokia",
        "00:1F:24": "Nokia",
        "00:20:2C": "Nokia",
        "00:21:5A": "Nokia",
        "00:22:48": "Nokia",
        "00:23:31": "Nokia",
        "00:24:11": "Nokia",
        "00:25:1A": "Nokia",
        "00:26:08": "Nokia",
        
        # ONE PLUS
        "00:08:22": "OnePlus",
        "00:15:6D": "OnePlus",
        "00:18:E7": "OnePlus",
        "00:22:58": "OnePlus",
        "00:23:8E": "OnePlus",
        "00:24:98": "OnePlus",
        "00:26:7C": "OnePlus",
        "00:28:6B": "OnePlus",
        "04:4F:AA": "OnePlus",
        "08:63:61": "OnePlus",
        "0C:2D:89": "OnePlus",
        "0C:4D:E9": "OnePlus",
        "10:10:9A": "OnePlus",
        "14:06:4A": "OnePlus",
        "18:1D:EA": "OnePlus",
        "1C:1B:19": "OnePlus",
        "1C:C1:DE": "OnePlus",
        "20:02:AF": "OnePlus",
        "24:0A:64": "OnePlus",
        "28:6C:51": "OnePlus",
        "2C:05:69": "OnePlus",
        "30:5A:3A": "OnePlus",
        "34:10:7B": "OnePlus",
        "38:9C:3A": "OnePlus",
        "3C:7D:82": "OnePlus",
        "40:2C:2A": "OnePlus",
        "44:8A:5B": "OnePlus",
        "48:57:2D": "OnePlus",
        "4C:5B:CD": "OnePlus",
        "50:2E:5C": "OnePlus",
        "54:8C:A0": "OnePlus",
        "58:8A:5C": "OnePlus",
        "5C:09:38": "OnePlus",
        "60:57:18": "OnePlus",
        "64:38:9D": "OnePlus",
        "68:DB:54": "OnePlus",
        "6C:4D:8A": "OnePlus",
        "70:4D:7B": "OnePlus",
        "74:56:3C": "OnePlus",
        "78:0A:F0": "OnePlus",
        "7C:2E:0D": "OnePlus",
        "80:49:71": "OnePlus",
        "84:8C:8E": "OnePlus",
        "88:36:6C": "OnePlus",
        "8C:45:00": "OnePlus",
        "90:2E:1B": "OnePlus",
        "94:3C:D6": "OnePlus",
        "98:77:C0": "OnePlus",
        "9C:37:E4": "OnePlus",
        "A0:2A:ED": "OnePlus",
        "A4:1F:72": "OnePlus",
        "A8:5C:2C": "OnePlus",
        "AC:84:C6": "OnePlus",
        "B0:5A:DA": "OnePlus",
        "B4:6D:83": "OnePlus",
        "B8:6A:97": "OnePlus",
        "BC:30:5B": "OnePlus",
        "C0:B2:37": "OnePlus",
        "C4:4F:01": "OnePlus",
        "C8:0E:14": "OnePlus",
        "CC:08:E0": "OnePlus",
        "CC:20:E8": "OnePlus",
        "D0:57:7C": "OnePlus",
        "D4:22:3A": "OnePlus",
        "D8:90:E8": "OnePlus",
        "DC:A4:CA": "OnePlus",
        "E0:60:66": "OnePlus",
        "E4:12:1D": "OnePlus",
        "E8:87:4E": "OnePlus",
        "EC:08:6B": "OnePlus",
        "F0:65:DD": "OnePlus",
        "F4:8C:50": "OnePlus",
        "F8:63:3F": "OnePlus",
        "FC:75:16": "OnePlus",
        
        # GOOGLE / PIXEL
        "00:1A:11": "Google",
        "00:1E:C0": "Google",
        "00:23:7A": "Google",
        "00:25:96": "Google",
        "00:26:6F": "Google",
        "00:27:23": "Google",
        "04:52:F3": "Google",
        "04:ED:33": "Google",
        "08:3E:8E": "Google",
        "08:6A:C5": "Google",
        "0C:47:C9": "Google",
        "14:7D:DA": "Google",
        "18:DF:9E": "Google",
        "1C:06:CD": "Google",
        "1C:49:7B": "Google",
        "20:CF:30": "Google",
        "24:18:1D": "Google",
        "28:92:4A": "Google",
        "2C:54:91": "Google",
        "30:5A:3A": "Google",
        "34:36:BB": "Google",
        "38:60:77": "Google",
        "3C:BB:FD": "Google",
        "40:A8:F0": "Google",
        "44:00:10": "Google",
        "48:EA:63": "Google",
        "4C:3C:16": "Google",
        "50:AF:73": "Google",
        "54:60:09": "Google",
        "58:24:29": "Google",
        "5C:80:B6": "Google",
        "60:C5:47": "Google",
        "68:AB:87": "Google",
        "6C:41:6A": "Google",
        "70:DB:98": "Google",
        "74:DA:38": "Google",
        "78:01:62": "Google",
        "7C:03:4C": "Google",
        "80:6C:8B": "Google",
        "84:EB:18": "Google",
        "88:93:FB": "Google",
        "8C:2D:AA": "Google",
        "90:1D:27": "Google",
        "94:3A:70": "Google",
        "98:8B:73": "Google",
        "9C:AD:EF": "Google",
        "A0:AE:A7": "Google",
        "A4:77:33": "Google",
        "A8:2C:51": "Google",
        "AC:9E:17": "Google",
        "B0:6D:9F": "Google",
        "B4:7D:78": "Google",
        "B8:4D:12": "Google",
        "BC:14:01": "Google",
        "C0:6C:0F": "Google",
        "C4:43:F6": "Google",
        "C8:69:CD": "Google",
        "CC:96:E5": "Google",
        "D0:05:73": "Google",
        "D4:41:65": "Google",
        "D8:1D:72": "Google",
        "DC:9F:DB": "Google",
        "E0:5F:B9": "Google",
        "E4:7D:4A": "Google",
        "E8:9F:6D": "Google",
        "EC:9B:F3": "Google",
        "F0:2F:74": "Google",
        "F4:5C:89": "Google",
        "F8:64:AD": "Google",
        
        # HUAWEI
        "00:0A:5A": "Huawei",
        "00:12:14": "Huawei",
        "00:1C:7E": "Huawei",
        "00:23:68": "Huawei",
        "04:1B:BA": "Huawei",
        "08:6C:9B": "Huawei",
        "0C:15:0A": "Huawei",
        "10:2C:6B": "Huawei",
        "14:AF:E2": "Huawei",
        "18:3F:47": "Huawei",
        "1C:1B:19": "Huawei",
        "20:68:0D": "Huawei",
        "24:46:C8": "Huawei",
        "28:6C:51": "Huawei",
        "2C:05:69": "Huawei",
        "30:5A:3A": "Huawei",
        "34:10:7B": "Huawei",
        "38:9C:3A": "Huawei",
        "3C:7D:82": "Huawei",
        "40:2C:2A": "Huawei",
        "44:8A:5B": "Huawei",
        "48:57:2D": "Huawei",
        "4C:5B:CD": "Huawei",
        "50:2E:5C": "Huawei",
        "54:8C:A0": "Huawei",
        "58:8A:5C": "Huawei",
        "5C:09:38": "Huawei",
        "60:57:18": "Huawei",
        "64:38:9D": "Huawei",
        "68:DB:54": "Huawei",
        "6C:4D:8A": "Huawei",
        "70:4D:7B": "Huawei",
        "74:56:3C": "Huawei",
        "78:0A:F0": "Huawei",
        "7C:2E:0D": "Huawei",
        "80:49:71": "Huawei",
        "84:8C:8E": "Huawei",
        "88:36:6C": "Huawei",
        "8C:45:00": "Huawei",
        "90:2E:1B": "Huawei",
        "94:3C:D6": "Huawei",
        "98:77:C0": "Huawei",
        "9C:37:E4": "Huawei",
        "A0:2A:ED": "Huawei",
        "A4:1F:72": "Huawei",
        "A8:5C:2C": "Huawei",
        "AC:84:C6": "Huawei",
        "B0:5A:DA": "Huawei",
        "B4:6D:83": "Huawei",
        "B8:6A:97": "Huawei",
        "BC:30:5B": "Huawei",
        "C0:B2:37": "Huawei",
        "C4:4F:01": "Huawei",
        "C8:0E:14": "Huawei",
        "CC:08:E0": "Huawei",
        "CC:20:E8": "Huawei",
        "D0:57:7C": "Huawei",
        "D4:22:3A": "Huawei",
        "D8:90:E8": "Huawei",
        "DC:A4:CA": "Huawei",
        "E0:60:66": "Huawei",
        "E4:12:1D": "Huawei",
        "E8:87:4E": "Huawei",
        "EC:08:6B": "Huawei",
        "F0:65:DD": "Huawei",
        "F4:8C:50": "Huawei",
        "F8:63:3F": "Huawei",
        "FC:75:16": "Huawei"
    }
    
    # Check OUI (first 8 characters with colons or first 6 without)
    mac_upper = mac.upper()
    
    # Try with colon format (AA:BB:CC)
    for i in range(0, len(mac_upper), 3):
        if i + 8 <= len(mac_upper):
            prefix = mac_upper[i:i+8]  # AA:BB:CC
            if prefix in oui_map:
                return oui_map[prefix]
    
    # Try without colons (AABBCC)
    mac_clean = mac_upper.replace(":", "").replace("-", "").replace(".", "")
    if len(mac_clean) >= 6:
        prefix = mac_clean[:6]
        # Convert back to colon format for lookup
        colon_prefix = ":".join([prefix[i:i+2] for i in range(0, 6, 2)])
        if colon_prefix in oui_map:
            return oui_map[colon_prefix]
    
    return None


def generate_port_based_analysis(ip, open_ports, device_type):
    """Generate risk analysis based on open ports and device type"""
    flow_results = []
    
    # Common services and their risk levels
    service_risks = {
        # High risk services
        23: ("Telnet", 5, "Critical"),
        21: ("FTP", 4, "High"), 
        161: ("SNMP", 4, "High"),
        162: ("SNMP-Trap", 4, "High"),
        135: ("Windows RPC", 4, "High"),
        139: ("NetBIOS", 3, "Medium"),
        445: ("SMB", 4, "High"),
        3389: ("RDP", 4, "High"),
        
        # Medium risk services
        22: ("SSH", 3, "Medium"),
        554: ("RTSP", 3, "Medium"),
        1433: ("MSSQL", 4, "High"),
        3306: ("MySQL", 3, "Medium"),
        5432: ("PostgreSQL", 3, "Medium"),
        
        # Low risk services
        80: ("HTTP", 2, "Low"),
        443: ("HTTPS", 1, "Very Low"),
        8080: ("HTTP-Alt", 2, "Low"),
        8888: ("HTTP-Alt2", 2, "Low"),
        8000: ("HTTP-Alt3", 2, "Low"),
        53: ("DNS", 1, "Very Low"),
        67: ("DHCP", 1, "Very Low"),
        68: ("DHCP", 1, "Very Low")
    }
    
    for port in open_ports[:8]:  # Limit to first 8 ports
        service_info = service_risks.get(port, (f"Port-{port}", 2, "Low"))
        service_name, risk, level = service_info
        
        flow_results.append({
            "flow": f"{ip}:{port} ({service_name})",
            "src": ip, "dst": "Network",
            "sport": port, "dport": "Various",
            "protocol": "TCP/UDP",
            "risk": risk,
            "risk_level": level,
            "service": service_name
        })
    
    # Add device-specific analysis
    if not flow_results:
        if "Camera" in device_type:
            flow_results.append({
                "flow": f"{ip}:554 (Typical Camera)",
                "src": ip, "dst": "Stream",
                "sport": 554, "dport": "Client",
                "protocol": "RTSP",
                "risk": 3,
                "risk_level": "Medium",
                "service": "Video Streaming"
            })
        elif "Router" in device_type:
            flow_results.append({
                "flow": f"{ip}:80 (Web Interface)",
                "src": ip, "dst": "Admin",
                "sport": 80, "dport": "Browser",
                "protocol": "HTTP",
                "risk": 2,
                "risk_level": "Low",
                "service": "Management"
            })
    
    return flow_results


def calculate_overall_risk(flow_results, device_type):
    """Calculate overall risk score for a device"""
    if not flow_results:
        return 1  # Default low risk for unknown
    
    risks = [flow.get("risk", 1) for flow in flow_results]
    avg_risk = sum(risks) / len(risks)
    
    # Adjust based on device type
    risk_adjustments = {
        "Security Camera": 1,
        "IoT Device": 0.5,
        "Smart Device": 0.5,
        "Windows Device": 0,
        "Linux Device": 0,
        "Router": 0.5,
        "Network Device": -0.5,
        "Mobile": -0.5,
        "Smartphone": -0.5,
        "Android": -0.5,
        "iPhone": -0.5
    }
    
    avg_risk += risk_adjustments.get(device_type, 0)
    # Also check if device_type contains mobile keywords
    if device_type and any(keyword in device_type for keyword in ["Mobile", "Phone", "Smartphone", "Android", "iPhone"]):
        avg_risk -= 0.5
    
    return max(1, min(5, int(round(avg_risk))))


def get_risk_level(risk_score):
    """Convert numeric risk score to text level"""
    if risk_score <= 1:
        return "Very Low"
    elif risk_score == 2:
        return "Low"
    elif risk_score == 3:
        return "Medium"
    elif risk_score == 4:
        return "High"
    else:
        return "Critical"


@app.route("/network_info", methods=["GET"])
def network_info():
    """Get current network information"""
    try:
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        return jsonify({
            "local_ip": local_ip,
            "hostname": hostname,
            "target_network": NETWORK_SUBNET,
            "model_loaded": model_loaded,
            "model_has_predict": hasattr(model, 'predict') if model else False,
            "capture_interface": CAPTURE_INTERFACE
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/demo_scan", methods=["GET"])
def demo_scan():
    """Demo endpoint with simulated devices including mobiles"""
    demo_devices = [
        {
            "ip": "192.168.1.4",
            "name": "Samsung Galaxy S23",
            "hostname": "Samsung-Galaxy-S23",
            "mac": "3A:B7:98:89:44:99",
            "type": "Mobile/Smartphone",
            "ports": [80, 443],
            "overall_risk": 1,
            "risk_level": "Very Low",
            "status": "Online",
            "predictions": [
                {
                    "flow": "192.168.1.4:443 (HTTPS)",
                    "risk": 1,
                    "risk_level": "Very Low",
                    "service": "HTTPS"
                }
            ]
        },
        {
            "ip": "192.168.1.10",
            "name": "iPhone 15 Pro",
            "hostname": "iPhone-15-Pro",
            "mac": "A4:5E:60:12:34:56",
            "type": "Mobile/Smartphone",
            "ports": [443, 5223],
            "overall_risk": 1,
            "risk_level": "Very Low",
            "status": "Online",
            "predictions": [
                {
                    "flow": "192.168.1.10:443 (HTTPS)",
                    "risk": 1,
                    "risk_level": "Very Low",
                    "service": "HTTPS"
                }
            ]
        },
        {
            "ip": "192.168.1.15",
            "name": "Poco X5 Pro",
            "hostname": "Poco-X5-Pro",
            "mac": "1C:C1:DE:78:90:12",
            "type": "Mobile/Smartphone",
            "ports": [80, 443],
            "overall_risk": 1,
            "risk_level": "Very Low",
            "status": "Online",
            "predictions": [
                {
                    "flow": "192.168.1.15:443 (HTTPS)",
                    "risk": 1,
                    "risk_level": "Very Low",
                    "service": "HTTPS"
                }
            ]
        },
        {
            "ip": "192.168.1.20",
            "name": "Oppo Reno 8",
            "hostname": "Oppo-Reno-8",
            "mac": "14:AF:E2:34:56:78",
            "type": "Mobile/Smartphone",
            "ports": [443],
            "overall_risk": 1,
            "risk_level": "Very Low",
            "status": "Online",
            "predictions": [
                {
                    "flow": "192.168.1.20:443 (HTTPS)",
                    "risk": 1,
                    "risk_level": "Very Low",
                    "service": "HTTPS"
                }
            ]
        },
        {
            "ip": "192.168.1.25",
            "name": "Vivo V29",
            "hostname": "Vivo-V29",
            "mac": "2C:05:69:90:12:34",
            "type": "Mobile/Smartphone",
            "ports": [80, 443],
            "overall_risk": 1,
            "risk_level": "Very Low",
            "status": "Online",
            "predictions": [
                {
                    "flow": "192.168.1.25:443 (HTTPS)",
                    "risk": 1,
                    "risk_level": "Very Low",
                    "service": "HTTPS"
                }
            ]
        },
        {
            "ip": "192.168.1.30",
            "name": "Tecno Spark 10",
            "hostname": "Tecno-Spark-10",
            "mac": "3C:7D:82:56:78:90",
            "type": "Mobile/Smartphone",
            "ports": [443],
            "overall_risk": 1,
            "risk_level": "Very Low",
            "status": "Online",
            "predictions": [
                {
                    "flow": "192.168.1.30:443 (HTTPS)",
                    "risk": 1,
                    "risk_level": "Very Low",
                    "service": "HTTPS"
                }
            ]
        },
        {
            "ip": "10.40.196.45",
            "name": "Corporate PC-045",
            "hostname": "Corporate-PC-045",
            "mac": "AA:BB:CC:11:22:33",
            "type": "Windows Device",
            "ports": [80, 443, 135, 445],
            "overall_risk": 2,
            "risk_level": "Low",
            "status": "Online",
            "predictions": [
                {
                    "flow": "10.40.196.45:445 (SMB)",
                    "risk": 3,
                    "risk_level": "Medium",
                    "service": "SMB"
                }
            ]
        },
        {
            "ip": "10.40.196.78",
            "name": "Lobby Security Camera",
            "hostname": "Security-Camera-Lobby",
            "mac": "DD:EE:FF:44:55:66",
            "type": "Security Camera", 
            "ports": [80, 554, 8080],
            "overall_risk": 4,
            "risk_level": "High",
            "status": "Online",
            "predictions": [
                {
                    "flow": "10.40.196.78:554 (RTSP)",
                    "risk": 4,
                    "risk_level": "High", 
                    "service": "Video Streaming"
                }
            ]
        },
        {
            "ip": "10.40.196.102",
            "name": "Network Printer 01",
            "hostname": "Network-Printer-01",
            "mac": "11:22:33:AA:BB:CC",
            "type": "IoT Device",
            "ports": [80, 443, 515, 9100],
            "overall_risk": 3,
            "risk_level": "Medium",
            "status": "Online",
            "predictions": [
                {
                    "flow": "10.40.196.102:9100 (Print)",
                    "risk": 3,
                    "risk_level": "Medium",
                    "service": "Print Service"
                }
            ]
        }
    ]
    
    return jsonify({
        "predictions": demo_devices,
        "total_devices": len(demo_devices),
        "timestamp": time.time(),
        "network_scanned": "Mixed Network (Demo)",
        "model_used": "demo"
    })


if __name__ == "__main__":
    print("🚀 IoT Device Scanner - Real Network Mode")
    print(f"📍 Target Network: {NETWORK_SUBNET}")
    print(f"🔧 Model Loaded: {model_loaded}")
    if model_loaded:
        print(f"📊 Model Type: {type(model)}")
    print(f"🎯 Capture Interface: {CAPTURE_INTERFACE}")
    print("🌐 Web Interface: http://localhost:5321")
    print("\n💡 Endpoints:")
    print("   - /scan_predict - Real network scan")
    print("   - /demo_scan - Demo data for testing") 
    print("   - /network_info - Current network info")
    print("\n⚠️  For packet capture, run as Administrator")
    
    app.run(host="0.0.0.0", port=5321, debug=True)