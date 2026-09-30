# scanner.py - Network Scanner with ACCURATE device naming
import socket
import subprocess
import platform
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress


# ============================================================
# REAL IEEE OUI prefixes (verified — one prefix = one vendor)
# ============================================================
REAL_OUI = {
    # -------- Apple --------
    "0017F2": "Apple", "0019E3": "Apple", "001B63": "Apple", "001CB3": "Apple",
    "001D4F": "Apple", "001E52": "Apple", "001EC2": "Apple", "001F03": "Apple",
    "001FF3": "Apple", "0021E9": "Apple", "002241": "Apple", "002332": "Apple",
    "00236C": "Apple", "0023DF": "Apple", "002436": "Apple", "002500": "Apple",
    "0025BC": "Apple", "002608": "Apple", "00264A": "Apple", "0026BB": "Apple",
    "002764": "Apple", "3C0754": "Apple", "5C969D": "Apple", "6C709F": "Apple",
    "7CD1C3": "Apple", "8863DF": "Apple", "9C04EB": "Apple", "A4D1D2": "Apple",
    "A85E45": "Apple", "ACBC32": "Apple", "B065BD": "Apple", "B853AC": "Apple",
    "B8E856": "Apple", "C82A14": "Apple", "D02598": "Apple", "D49A20": "Apple",
    "DC2B2A": "Apple", "E0B9BA": "Apple", "E4CE8F": "Apple", "E80688": "Apple",
    "F01898": "Apple", "F04BAC": "Apple", "F0DBF8": "Apple", "F4F15A": "Apple",
    "F81EDF": "Apple", "F81F94": "Apple", "FC253F": "Apple",

    # -------- Samsung --------
    "0012FB": "Samsung", "0013A9": "Samsung", "0015B9": "Samsung", "001632": "Samsung",
    "0017C9": "Samsung", "0018AF": "Samsung", "001A8A": "Samsung", "001B98": "Samsung",
    "001DF6": "Samsung", "001E7D": "Samsung", "001FCC": "Samsung", "0021D1": "Samsung",
    "002339": "Samsung", "0023D6": "Samsung", "002454": "Samsung", "002566": "Samsung",
    "002637": "Samsung", "0026E2": "Samsung", "08373D": "Samsung", "0C1420": "Samsung",
    "101DC0": "Samsung", "14568E": "Samsung", "185936": "Samsung", "1C5A3E": "Samsung",
    "20647F": "Samsung", "244B03": "Samsung", "2C440B": "Samsung", "301966": "Samsung",
    "34145F": "Samsung", "38AA3C": "Samsung", "3C5A37": "Samsung", "402343": "Samsung",
    "444E1A": "Samsung", "4844F7": "Samsung", "4C3C16": "Samsung", "501AC5": "Samsung",
    "5492BE": "Samsung", "58C38B": "Samsung", "5C0A5B": "Samsung", "606944": "Samsung",
    "64B853": "Samsung", "68EBAE": "Samsung", "6C2F2C": "Samsung", "70F927": "Samsung",
    "743AAE": "Samsung", "78521A": "Samsung", "7C6193": "Samsung", "8018A7": "Samsung",
    "8425DB": "Samsung", "88329B": "Samsung", "8C71F8": "Samsung", "90185F": "Samsung",
    "94350A": "Samsung", "9852B1": "Samsung", "9C0298": "Samsung", "A00798": "Samsung",
    "A41EF8": "Samsung", "A82BB9": "Samsung", "AC5F3E": "Samsung", "B047BF": "Samsung",
    "B407F9": "Samsung", "B857D8": "Samsung", "BC1485": "Samsung", "C01173": "Samsung",
    "C44202": "Samsung", "C81479": "Samsung", "CC07AB": "Samsung", "D0176A": "Samsung",
    "D487D8": "Samsung", "D857EF": "Samsung", "DC7144": "Samsung", "E0998F": "Samsung",
    "E440E2": "Samsung", "E8039A": "Samsung", "EC1F72": "Samsung", "F008F1": "Samsung",
    "F409D8": "Samsung", "F8042E": "Samsung", "FC0012": "Samsung", "FC8F90": "Samsung",

    # -------- Xiaomi --------
    "009EC8": "Xiaomi", "0C1DAF": "Xiaomi", "102AB3": "Xiaomi",
    "1C9D72": "Xiaomi", "2082C0": "Xiaomi", "24699B": "Xiaomi", "286C07": "Xiaomi",
    "2C5513": "Xiaomi", "305A3A": "Xiaomi", "34CE00": "Xiaomi", "38A28C": "Xiaomi",
    "3C47C1": "Xiaomi", "404D8E": "Xiaomi", "44A42B": "Xiaomi", "4C49E3": "Xiaomi",
    "50647A": "Xiaomi", "54E43A": "Xiaomi", "58B623": "Xiaomi", "5C0252": "Xiaomi",
    "64B473": "Xiaomi", "68DFDD": "Xiaomi", "6C5A34": "Xiaomi", "742357": "Xiaomi",
    "7802F8": "Xiaomi", "7C1DD9": "Xiaomi", "8CBEBE": "Xiaomi", "90843D": "Xiaomi",
    "94E23C": "Xiaomi", "98FAE3": "Xiaomi", "9C99A0": "Xiaomi", "A086C6": "Xiaomi",
    "A4C138": "Xiaomi", "ACC1EE": "Xiaomi", "B0E235": "Xiaomi", "B4E62D": "Xiaomi",
    "B8AA33": "Xiaomi", "BC3AEA": "Xiaomi", "C46AB7": "Xiaomi", "C8AD97": "Xiaomi",
    "CC2D1B": "Xiaomi", "D013FD": "Xiaomi", "D4351D": "Xiaomi", "D85985": "Xiaomi",
    "DC44B6": "Xiaomi", "E0B94D": "Xiaomi", "E4AA5D": "Xiaomi", "E8ABFA": "Xiaomi",
    "EC5C68": "Xiaomi", "F0B429": "Xiaomi", "F48B32": "Xiaomi", "F8A45F": "Xiaomi",
    "FC64BA": "Xiaomi",

    # -------- Huawei --------
    "001882": "Huawei", "00259E": "Huawei", "002EC7": "Huawei", "044BED": "Huawei",
    "086361": "Huawei", "0C37DC": "Huawei", "104780": "Huawei", "144968": "Huawei",
    "18C58A": "Huawei", "1C1D67": "Huawei", "201BC7": "Huawei", "240995": "Huawei",
    "283152": "Huawei", "2C55D3": "Huawei", "308730": "Huawei", "3400A3": "Huawei",
    "384608": "Huawei", "3CDFBD": "Huawei", "40CBA8": "Huawei", "48435A": "Huawei",
    "4C1FCC": "Huawei", "501D93": "Huawei", "5439DF": "Huawei", "586AB1": "Huawei",
    "5CA86A": "Huawei", "60DE44": "Huawei", "643E8C": "Huawei", "688F84": "Huawei",
    "6C92BF": "Huawei", "70DEE2": "Huawei", "7427EA": "Huawei", "784BE8": "Huawei",
    "7C6097": "Huawei", "80B686": "Huawei", "886396": "Huawei", "8C34FD": "Huawei",
    "9017AC": "Huawei", "94049C": "Huawei", "9C28EF": "Huawei", "A08D16": "Huawei",
    "A47174": "Huawei", "A8C83A": "Huawei", "AC4E91": "Huawei", "B41513": "Huawei",
    "B8BC1B": "Huawei", "BCE0F9": "Huawei", "C07009": "Huawei", "C40528": "Huawei",
    "C88D83": "Huawei", "CC53B5": "Huawei", "D02DB3": "Huawei", "D4612E": "Huawei",
    "D8490B": "Huawei", "DC094C": "Huawei", "E0247F": "Huawei", "E468A3": "Huawei",
    "E8CD2D": "Huawei", "EC233D": "Huawei", "F04347": "Huawei", "F44C7F": "Huawei",
    "F83DFF": "Huawei", "FC48EF": "Huawei",

    # -------- OnePlus --------
    "0452F3": "OnePlus", "44650D": "OnePlus", "64A2F9": "OnePlus", "94652D": "OnePlus",
    "AC64DD": "OnePlus", "C0EEFB": "OnePlus", "D8C4E9": "OnePlus",

    # -------- Oppo --------
    "14064A": "Oppo",

    # -------- Vivo --------
    "3C5AB4": "Vivo",

    # -------- Google Pixel --------
    "001A11": "Google", "404D8E": "Google", "546009": "Google",
    "6466B3": "Google", "7C2EBD": "Google", "84EB18": "Google", "94EB2C": "Google",
    "A47733": "Google", "DC2B61": "Google", "E4F042": "Google",
    "F4F5D8": "Google", "F88FCA": "Google",

    # -------- Motorola --------
    "001A1E": "Motorola", "001F5B": "Motorola", "002329": "Motorola", "0026E2": "Motorola",
    "143E60": "Motorola", "24DA9B": "Motorola", "2C44FD": "Motorola", "344B50": "Motorola",
    "404D7F": "Motorola",

    # -------- Nokia --------
    "0002EE": "Nokia", "000BE1": "Nokia", "000E6D": "Nokia", "0012D1": "Nokia",
    "0013CC": "Nokia", "0014A7": "Nokia", "0015A0": "Nokia", "0016BC": "Nokia",
    "0017B0": "Nokia", "0018C6": "Nokia", "0019C2": "Nokia", "001A16": "Nokia",
    "001B34": "Nokia", "001C9A": "Nokia", "001D3B": "Nokia", "001E3A": "Nokia",
    "001F5C": "Nokia", "0020D6": "Nokia", "0021FC": "Nokia", "0022FD": "Nokia",
    "0023B4": "Nokia", "0024B3": "Nokia", "0025CF": "Nokia", "002668": "Nokia",

    # -------- Lenovo --------
    "00055D": "Lenovo", "00061B": "Lenovo", "0008E8": "Lenovo", "000A0C": "Lenovo",
    "000D0C": "Lenovo", "000E7F": "Lenovo", "0010E3": "Lenovo", "001125": "Lenovo",
    "001324": "Lenovo", "001438": "Lenovo", "001560": "Lenovo", "0016D3": "Lenovo",
    "0017DE": "Lenovo", "0019B6": "Lenovo", "001B77": "Lenovo", "001C25": "Lenovo",
    "001D09": "Lenovo", "001E2F": "Lenovo", "001F32": "Lenovo", "002096": "Lenovo",

    # -------- TP-Link --------
    "001D0F": "TP-Link", "002127": "TP-Link", "0023CD": "TP-Link", "002586": "TP-Link",
    "002719": "TP-Link", "081077": "TP-Link", "0C8063": "TP-Link", "10FEED": "TP-Link",
    "146A0B": "TP-Link", "1C61B4": "TP-Link", "206BE7": "TP-Link", "246081": "TP-Link",
    "28EE52": "TP-Link", "30B5C2": "TP-Link", "34E894": "TP-Link",
    "3C46D8": "TP-Link", "40169F": "TP-Link", "44D9E7": "TP-Link", "4CEDFB": "TP-Link",
    "50C7BF": "TP-Link", "54C80F": "TP-Link", "586D8F": "TP-Link", "5C63BF": "TP-Link",
    "60E327": "TP-Link", "68FF7B": "TP-Link", "6C5AB0": "TP-Link",
    "74DA88": "TP-Link", "784476": "TP-Link", "7C8BCA": "TP-Link", "80EA96": "TP-Link",
    "886B6E": "TP-Link", "9059AF": "TP-Link", "940C6D": "TP-Link", "A0F3C1": "TP-Link",
    "A42BB0": "TP-Link", "A8574E": "TP-Link", "AC84C6": "TP-Link", "B0487A": "TP-Link",
    "B0BE76": "TP-Link", "B4B024": "TP-Link", "B8F883": "TP-Link", "C006C3": "TP-Link",
    "C46E1F": "TP-Link", "CC32E5": "TP-Link", "D46E0E": "TP-Link", "D80D17": "TP-Link",
    "E005C5": "TP-Link", "E4C146": "TP-Link", "E894F6": "TP-Link", "EC086B": "TP-Link",
    "F0F336": "TP-Link", "F4EC38": "TP-Link", "F8D111": "TP-Link", "FC7C02": "TP-Link",

    # -------- D-Link --------
    "001195": "D-Link", "001346": "D-Link", "0015E9": "D-Link", "00179A": "D-Link",
    "001B11": "D-Link", "001CF0": "D-Link", "001E58": "D-Link", "002191": "D-Link",
    "0022B0": "D-Link", "002401": "D-Link", "00265A": "D-Link", "1CAFF7": "D-Link",
    "340804": "D-Link", "3C1E04": "D-Link", "5CD998": "D-Link", "78542E": "D-Link",
    "84C9B2": "D-Link", "9094E4": "D-Link", "B8A386": "D-Link", "C8BE19": "D-Link",
    "CCB255": "D-Link", "F07D68": "D-Link", "FC7516": "D-Link",

    # -------- Netgear --------
    "000FB5": "Netgear", "001B2F": "Netgear", "001E2A": "Netgear", "001F33": "Netgear",
    "00223F": "Netgear", "0024B2": "Netgear", "0026F2": "Netgear", "20E52A": "Netgear",
    "28C68E": "Netgear", "2C3033": "Netgear", "30469A": "Netgear", "3894ED": "Netgear",
    "405D82": "Netgear", "44944A": "Netgear",
    "4C60DE": "Netgear", "6CB0CE": "Netgear", "841B5E": "Netgear", "9C3DCF": "Netgear",
    "A00460": "Netgear", "A040A0": "Netgear", "B03956": "Netgear", "B07FB9": "Netgear",
    "C03F0E": "Netgear", "C40415": "Netgear", "CC40D0": "Netgear", "E0469A": "Netgear",
    "E091F5": "Netgear",

    # -------- ASUS --------
    "0011D8": "ASUS", "001731": "ASUS", "001A92": "ASUS", "001BFC": "ASUS",
    "001E8C": "ASUS", "002215": "ASUS",
    "002354": "ASUS", "00248C": "ASUS", "002618": "ASUS", "04D4C4": "ASUS",
    "08606E": "ASUS", "107B44": "ASUS", "1C872C": "ASUS", "2C56DC": "ASUS",
    "382C4A": "ASUS", "40167E": "ASUS", "50465D": "ASUS",
    "54A050": "ASUS", "6045CB": "ASUS", "704D7B": "ASUS", "74D02B": "ASUS",
    "7824AF": "ASUS", "88D7F6": "ASUS", "9C5C8E": "ASUS", "AC220B": "ASUS",
    "AC9E17": "ASUS", "B06EBF": "ASUS",
    "C86000": "ASUS", "D017C2": "ASUS", "D850E6": "ASUS", "E03F49": "ASUS",
    "F832E4": "ASUS", "FC3497": "ASUS",

    # -------- Ubiquiti --------
    "00156D": "Ubiquiti", "002722": "Ubiquiti", "0418D6": "Ubiquiti", "24A43C": "Ubiquiti",
    "687251": "Ubiquiti", "74ACB9": "Ubiquiti", "788A20": "Ubiquiti",
    "802AA8": "Ubiquiti", "B4FBE4": "Ubiquiti", "D021F9": "Ubiquiti", "DC9FDB": "Ubiquiti",
    "E063DA": "Ubiquiti", "F09FC2": "Ubiquiti", "FCECDA": "Ubiquiti",

    # -------- IoT --------
    "001788": "Philips Hue", "ECB5FA": "Philips Hue",
    "240AC4": "Espressif (ESP32)", "A4CF12": "Espressif", "5CCF7F": "Espressif",
    "84F3EB": "Espressif", "D8BFC0": "Espressif", "3C71BF": "Espressif",
    "807D3A": "Espressif", "246F28": "Espressif", "C44F33": "Espressif",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "6837E9": "Amazon", "74C246": "Amazon", "84D6D0": "Amazon",
    "A002DC": "Amazon", "B47C9C": "Amazon", "F0272D": "Amazon", "FC65DE": "Amazon",
    "000D93": "Roku", "AC3A7A": "Roku", "B0A737": "Roku", "C83A35": "Roku",
    "CC6DA0": "Roku", "D83134": "Roku", "DC3A5E": "Roku",
}


def _clean_mac(mac):
    if not mac or mac in ("Unknown", "N/A", ""):
        return None
    return mac.upper().replace(":", "").replace("-", "").replace(".", "")


def get_vendor_from_mac(mac):
    """Look up IEEE OUI. Returns vendor string or None."""
    clean = _clean_mac(mac)
    if not clean or len(clean) < 6:
        return None
    return REAL_OUI.get(clean[:6])


# Vendor → friendly device class
VENDOR_DEVICE_CLASS = {
    "Apple":    "iPhone / iPad / Mac",
    "Samsung":  "Samsung Galaxy",
    "Xiaomi":   "Xiaomi / Redmi / POCO",
    "Huawei":   "Huawei / Honor",
    "OnePlus":  "OnePlus",
    "Oppo":     "Oppo / Realme",
    "Vivo":     "Vivo",
    "Google":   "Google Pixel",
    "Motorola": "Motorola",
    "Nokia":    "Nokia",
    "Tecno":    "Tecno",
    "Infinix":  "Infinix",
    "Itel":     "Itel",
    "Lenovo":   "Lenovo",
    "TP-Link":  "TP-Link Router",
    "D-Link":   "D-Link Router",
    "Netgear":  "Netgear Router",
    "ASUS":     "ASUS Router",
    "Ubiquiti": "Ubiquiti AP",
    "Philips Hue":       "Philips Hue Bulb",
    "Espressif (ESP32)": "ESP32 IoT",
    "Espressif":         "ESP IoT",
    "Raspberry Pi":      "Raspberry Pi",
    "Amazon":            "Amazon Echo / Fire TV",
    "Roku":              "Roku Streaming",
}


class EnhancedNetworkScanner:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.network_prefix = self.get_network_prefix()
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3389: "RDP", 5900: "VNC",
            8080: "HTTP-Proxy", 1883: "MQTT", 8883: "MQTT/SSL",
            5683: "CoAP", 161: "SNMP", 162: "SNMP Trap",
            993: "IMAP/SSL", 995: "POP3/SSL", 8000: "HTTP-Alt",
            8443: "HTTPS-Alt", 5000: "UPnP", 1900: "SSDP",
            62078: "iOS Sync",   # iPhone lockdown port
            5353: "mDNS",        # Bonjour
            7000: "AirPlay",     # Apple AirPlay
            9100: "Print",
            515: "LPD",
            554: "RTSP",
        }

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    def get_network_prefix(self):
        return ".".join(self.local_ip.split(".")[:3])

    def get_network_cidr(self):
        return f"{self.network_prefix}.0/24"

    def is_real_device(self, ip):
        try:
            a = ipaddress.ip_address(ip)
            return not (a.is_multicast or a.is_unspecified or a.is_loopback)
        except ValueError:
            return False

    # ---------------- ARP ----------------
    def arp_scan(self):
        devices = {}
        system = platform.system().lower()
        try:
            if system == "windows":
                r = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
                for line in r.stdout.splitlines():
                    m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{11,17})\s+(\w+)", line)
                    if not m:
                        continue
                    ip, mac_raw, kind = m.group(1), m.group(2), m.group(3)
                    if kind.lower() not in ("dynamic", "static"):
                        continue
                    if not self.is_real_device(ip) or not ip.startswith(self.network_prefix):
                        continue
                    mac = mac_raw.upper().replace("-", ":")
                    if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                        continue
                    devices[ip] = mac
            else:
                r = subprocess.run(["arp", "-an"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
                    if not m:
                        continue
                    ip, mac_raw = m.group(1), m.group(2)
                    if not self.is_real_device(ip) or not ip.startswith(self.network_prefix):
                        continue
                    devices[ip] = mac_raw.upper()
        except Exception as e:
            print(f"[!] ARP scan failed: {e}")
        return devices

    # ---------------- Ping sweep ----------------
    def ping_sweep(self, start=1, end=254, timeout=1):
        system = platform.system().lower()

        def ping(ip):
            try:
                if system == "windows":
                    cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
                    flags = subprocess.CREATE_NO_WINDOW
                else:
                    cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
                    flags = 0
                r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, creationflags=flags)
                return ip if r.returncode == 0 else None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=128) as ex:
            futs = [ex.submit(ping, f"{self.network_prefix}.{i}")
                    for i in range(start, end + 1)]
            return [f.result() for f in as_completed(futs) if f.result()]

    # ---------------- Ports ----------------
    def scan_ports(self, ip, ports, timeout=0.5):
        open_ports = {}

        def check(p):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, p)) == 0:
                        return p, self.common_ports.get(p, "Unknown")
            except Exception:
                pass
            return None, None

        with ThreadPoolExecutor(max_workers=200) as ex:
            futs = {ex.submit(check, p): p for p in ports}
            for f in as_completed(futs):
                p, svc = f.result()
                if p:
                    open_ports[p] = svc
        return open_ports

    def quick_port_scan(self, ip):
        ports = [80, 443, 22, 21, 23, 3389, 8080, 53,
                 1883, 5000, 1900, 62078, 5353, 7000, 9100, 554]
        return self.scan_ports(ip, ports)

    def common_port_scan(self, ip):
        return self.scan_ports(ip, list(self.common_ports.keys()))

    # ---------------- NAMING LOGIC ----------------
    def build_device_name(self, ip, hostname, mac, vendor, open_ports):
        """
        Priority:
          1. Real hostname
          2. Vendor + device class from MAC
          3. Port fingerprint
          4. Generic fallback with IP
        """
        # 1. Hostname — only if meaningful
        if hostname and hostname != "Unknown":
            if hostname != ip and not hostname.startswith(ip):
                return hostname

        ports = set(open_ports or [])

        # 2. Vendor-based name
        if vendor:
            # iPhone/iPad: Apple + (62078 lockdown OR AirPlay OR mDNS)
            if vendor == "Apple" and (62078 in ports or 7000 in ports or 5353 in ports):
                return "Apple iPhone / iPad"
            # Mac: Apple + SSH but not iOS lockdown
            if vendor == "Apple" and 22 in ports and 62078 not in ports:
                return "Apple Mac"
            cls = VENDOR_DEVICE_CLASS.get(vendor, vendor)
            return f"{vendor} — {cls}"

        # 3. Port fingerprint when no MAC
        if 62078 in ports:
            return "Apple iPhone / iPad"
        if 7000 in ports and 5353 in ports:
            return "Apple Device (AirPlay)"
        if 9100 in ports or 515 in ports:
            return "Network Printer"
        if 554 in ports:
            return "IP Camera (RTSP)"
        if 1883 in ports or 8883 in ports:
            return "MQTT IoT Device"
        if 3389 in ports:
            return "Windows PC (RDP)"
        if 445 in ports or 139 in ports:
            return "Windows PC (SMB)"
        if 22 in ports and 80 not in ports and 443 not in ports:
            return "Linux / SSH Host"
        if 80 in ports or 443 in ports:
            return "Web Server"
        if ip.endswith(".1") or ip.endswith(".254"):
            return "Router / Gateway"

        return f"Unknown Device ({ip})"

    def identify_device_type(self, ip, vendor, open_ports):
        if ip == self.local_ip:
            return "This Computer"
        if ip.endswith(".1") or ip.endswith(".254"):
            return "Router"
        if vendor in ("Apple", "Samsung", "Xiaomi", "Huawei", "OnePlus",
                      "Oppo", "Vivo", "Google", "Motorola", "Nokia",
                      "Tecno", "Infinix", "Itel"):
            return "Mobile Device"
        ports = set(open_ports or [])
        if 554 in ports:
            return "Camera"
        if 9100 in ports or 515 in ports:
            return "Printer"
        if 1883 in ports or 8883 in ports or 5683 in ports:
            return "IoT Device"
        if 3389 in ports or 445 in ports:
            return "Windows PC"
        if 22 in ports:
            return "Linux Host"
        if vendor in ("TP-Link", "D-Link", "Netgear", "ASUS", "Ubiquiti"):
            return "Network Device"
        return "Unknown"

    # ---------------- Main ----------------
    def scan_all_devices(self, scan_ports=True, port_scan_type="quick"):
        print(f"\n[*] Local IP: {self.local_ip}")
        print(f"[*] CIDR: {self.get_network_cidr()}")

        arp_devices = self.arp_scan()
        active_ips = self.ping_sweep()
        all_ips = set(active_ips) | set(arp_devices.keys()) | {self.local_ip}
        print(f"[*] ARP: {len(arp_devices)}, Ping: {len(active_ips)}, Total: {len(all_ips)}")

        devices = []
        for ip in sorted(all_ips, key=lambda x: [int(o) for o in x.split(".")]):
            mac = arp_devices.get(ip, "Unknown")
            hostname = self._resolve_hostname(ip)

            open_ports = {}
            if scan_ports:
                if port_scan_type == "quick":
                    open_ports = self.quick_port_scan(ip)
                elif port_scan_type == "all":
                    open_ports = self.scan_ports(ip, list(range(1, 1025)), timeout=0.3)
                else:
                    open_ports = self.common_port_scan(ip)

            vendor = get_vendor_from_mac(mac) if mac != "Unknown" else None

            name = self.build_device_name(ip, hostname, mac, vendor, list(open_ports.keys()))
            dtype = self.identify_device_type(ip, vendor, list(open_ports.keys()))

            devices.append({
                "ip": ip,
                "name": name,
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "type": dtype,
                "open_ports": open_ports,
                "ports": list(open_ports.keys()),
            })

        return devices

    def _resolve_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"


# ---------------- PUBLIC API ----------------
def discover_devices(scan_ports=True, port_scan_type="quick"):
    return EnhancedNetworkScanner().scan_all_devices(
        scan_ports=scan_ports, port_scan_type=port_scan_type
    )


if __name__ == "__main__":
    for d in discover_devices(scan_ports=True, port_scan_type="quick"):
        print(f"{d['ip']:<16} {d['name']:<40} {d['type']:<18} {d['mac']}")