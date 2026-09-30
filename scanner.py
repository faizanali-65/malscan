# scanner.py - Network Scanner Module
import socket
import subprocess
import platform
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress


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
            993: "IMAP/SSL", 995: "POP3/SSL"
        }
        
        # Mobile device OUI prefixes
        self.mobile_ouis = {
            "F0:2F:74": "Google",
            "8C:85:80": "Apple",
            "A4:C0:E1": "Samsung",
            "D0:57:7B": "Samsung",
            "8C:58:77": "Xiaomi",
            "00:9A:CD": "Huawei",
            "F8:95:C7": "Huawei",
            "B4:52:7D": "OnePlus",
            "38:CA:DA": "OnePlus",
            "34:BB:1F": "Motorola"
        }
        
        self.iot_ouis = {
            "34:EA:34": "Philips Hue",
            "00:17:88": "Philips Hue",
            "B4:E6:2D": "ESP32",
            "24:0A:C4": "Xiaomi IoT",
            "A4:CF:12": "ESP8266",
            "DC:4F:22": "TP-Link",
            "C0:25:E9": "TP-Link",
            "44:D2:CA": "Belkin",
            "EC:1A:59": "Belkin"
        }

    # ---------------- BASIC INFO ----------------
    def get_local_ip(self):
        """Get the local IP address"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip

    def get_network_prefix(self):
        """Get the first three octets of IP for network scanning"""
        return ".".join(self.local_ip.split(".")[:3])

    def is_real_device(self, ip):
        """Validate IP address"""
        try:
            addr = ipaddress.ip_address(ip)
            return not (addr.is_multicast or addr.is_unspecified)
        except:
            return False

    # ---------------- HOSTNAME ----------------
    def resolve_hostname(self, ip):
        """Resolve IP to hostname"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            # Try reverse DNS
            try:
                return socket.getnameinfo((ip, 0), 0)[0]
            except:
                return "Unknown"

    # ---------------- PING SWEEP ----------------
    def ping_sweep(self, start=1, end=254, timeout=1):
        """Ping sweep to discover active hosts"""
        print(f"🔍 Scanning {self.network_prefix}.{start}-{end}")

        def ping(ip):
            """Ping a single IP"""
            try:
                param = "-n" if platform.system().lower() == "windows" else "-c"
                timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
                timeout_val = str(timeout * 1000) if platform.system().lower() == "windows" else str(timeout)
                
                command = ["ping", param, "1", timeout_param, timeout_val, ip]
                
                result = subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0
                )
                return ip if result.returncode == 0 else None
            except:
                return None

        # Use ThreadPoolExecutor for concurrent pinging
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(ping, f"{self.network_prefix}.{i}") 
                      for i in range(start, end + 1)]
            
            active_ips = []
            for future in as_completed(futures):
                result = future.result()
                if result:
                    active_ips.append(result)
                    
        return active_ips

    # ---------------- ARP SCAN ----------------
    def arp_scan(self):
        """Perform ARP scan to get MAC addresses"""
        devices = {}
        try:
            # For Windows
            if platform.system().lower() == "windows":
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True, shell=True)
                for line in result.stdout.splitlines():
                    if "dynamic" in line.lower() or "static" in line.lower():
                        parts = line.split()
                        if len(parts) >= 2 and "." in parts[0]:
                            ip = parts[0]
                            mac = parts[1].replace("-", ":").upper() if "-" in parts[1] else parts[1].upper()
                            if ip.startswith(self.network_prefix) and self.is_real_device(ip):
                                devices[ip] = mac
            # For Linux/Mac
            else:
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and ":" in parts[3] and "." in parts[1].strip("()"):
                        ip = parts[1].strip("()")
                        mac = parts[3].upper()
                        if ip.startswith(self.network_prefix) and self.is_real_device(ip):
                            devices[ip] = mac
        except Exception as e:
            print(f"⚠️ ARP scan warning: {e}")
            
        return devices

    # ---------------- PORT SCANNING ----------------
    def scan_ports(self, ip, ports, timeout=0.5):
        """Scan specific ports on an IP"""
        open_ports = {}
        
        def check_port(port):
            """Check if a port is open"""
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        return port, self.common_ports.get(port, "Unknown")
            except:
                pass
            return None, None

        # Scan ports concurrently
        with ThreadPoolExecutor(max_workers=200) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                port, service = future.result()
                if port:
                    open_ports[port] = service
                    
        return open_ports

    def quick_port_scan(self, ip):
        """Quick scan of most common ports"""
        quick_ports = [80, 443, 22, 21, 23, 3389, 8080, 53]
        return self.scan_ports(ip, quick_ports)

    def common_port_scan(self, ip):
        """Scan all common ports"""
        return self.scan_ports(ip, list(self.common_ports.keys()))

    def full_port_scan(self, ip, max_ports=1000):
        """Full port scan (adjustable range)"""
        return self.scan_ports(ip, list(range(1, max_ports + 1)), timeout=0.3)

    # ---------------- BANNER GRABBING ----------------
    def grab_banner(self, ip, port, timeout=2):
        """Grab service banner from open port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))
                sock.send(b"\r\n\r\n")
                banner = sock.recv(1024)
                return banner.decode(errors="ignore").strip()
        except:
            return None

    # ---------------- DEVICE IDENTIFICATION ----------------
    def identify_device_by_mac(self, mac):
        """Identify device type by MAC address OUI"""
        if mac == "Unknown" or not mac:
            return "Unknown"
            
        mac_clean = mac.replace(":", "").replace("-", "").upper()
        
        # Check mobile device OUIs
        for oui, vendor in self.mobile_ouis.items():
            if mac_clean.startswith(oui.replace(":", "")):
                return f"Mobile Device ({vendor})"
                
        # Check IoT device OUIs
        for oui, vendor in self.iot_ouis.items():
            if mac_clean.startswith(oui.replace(":", "")):
                return f"IoT Device ({vendor})"
                
        # Check for common patterns
        if mac_clean.startswith("0017") or mac_clean.startswith("001B"):  # Apple
            return "Apple Device"
        elif mac_clean.startswith("000D93"):  # Roku
            return "Streaming Device (Roku)"
        elif mac_clean.startswith("001A11"):  # Google
            return "Google Device"
            
        return "Network Device"

    def identify_device_by_ports(self, open_ports):
        """Identify device type by open ports"""
        if not open_ports:
            return "Generic Device"
            
        port_services = {port: self.common_ports.get(port, "") for port in open_ports}
        
        # Check for IoT patterns
        iot_ports = {1883, 8883, 5683, 161, 162}
        if any(port in iot_ports for port in open_ports):
            return "IoT Device"
            
        # Check for web servers
        if any(port in {80, 443, 8080} for port in open_ports):
            return "Web Server"
            
        # Check for remote access
        if any(port in {22, 23, 3389, 5900} for port in open_ports):
            return "Remote Access Device"
            
        return "Network Device"

    def identify_device(self, ip, mac="Unknown", open_ports=None):
        """Main device identification function"""
        if ip == self.local_ip:
            return "This Computer"
            
        # Router identification
        if ip.endswith(".1") or ip.endswith(".254"):
            return "Router/Gateway"
            
        # Try MAC-based identification first
        if mac != "Unknown":
            mac_based = self.identify_device_by_mac(mac)
            if mac_based != "Network Device":
                return mac_based
                
        # Fall back to port-based identification
        if open_ports:
            port_based = self.identify_device_by_ports(open_ports)
            return port_based
            
        # Final fallback
        last_octet = int(ip.split('.')[-1])
        if 100 <= last_octet <= 199:  # Common DHCP range
            return "Mobile"
            
        return "Network/IoT Device"

    # ---------------- MAIN SCAN FUNCTION ----------------
    def scan_all_devices(self, scan_ports=True, port_scan_type="common"):
        """Main scanning function - returns list of devices"""
        print("\n🚀 Starting Enhanced Network Scan")
        print("=" * 60)
        print(f"Local IP: {self.local_ip}")
        print(f"Network: {self.network_prefix}.0/24")
        
        # Step 1: Discover active devices
        print("\n📡 Phase 1: Discovering active devices...")
        active_ips = self.ping_sweep()
        arp_devices = self.arp_scan()
        
        print(f"✅ Found {len(active_ips)} active IPs via ping")
        print(f"✅ Found {len(arp_devices)} devices via ARP")
        
        # Combine results
        all_ips = set(active_ips)
        all_ips.update(arp_devices.keys())
        
        if not all_ips:
            print("❌ No devices found!")
            return []
            
        print(f"📊 Total unique devices: {len(all_ips)}")
        
        # Step 2: Gather detailed info for each device
        print("\n📡 Phase 2: Gathering device information...")
        devices = []
        
        for i, ip in enumerate(sorted(all_ips), 1):
            print(f"  Processing device {i}/{len(all_ips)}: {ip}", end="\r")
            
            # Basic info
            mac = arp_devices.get(ip, "Unknown")
            hostname = self.resolve_hostname(ip)
            
            # Port scanning (if requested)
            open_ports = {}
            banners = {}
            
            if scan_ports:
                if port_scan_type == "quick":
                    open_ports = self.quick_port_scan(ip)
                elif port_scan_type == "all":
                    open_ports = self.full_port_scan(ip, max_ports=500)  # Limited for speed
                else:  # common
                    open_ports = self.common_port_scan(ip)
                
                # Grab banners for up to 3 ports
                for port in list(open_ports.keys())[:3]:
                    banner = self.grab_banner(ip, port)
                    if banner:
                        banners[port] = banner[:100]  # Limit banner length
            
            # Device type identification
            device_type = self.identify_device(ip, mac, open_ports.keys())
            
            # Build device info
            device_info = {
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "type": device_type,
                "open_ports": open_ports,
                "banners": banners,
                "detection_methods": []
            }
            
            # Record detection methods
            if ip in active_ips:
                device_info["detection_methods"].append("ping")
            if ip in arp_devices:
                device_info["detection_methods"].append("arp")
                
            devices.append(device_info)
            
        print(f"\n✅ Scan completed. Processed {len(devices)} devices.")
        
        return devices

    # ---------------- DISPLAY RESULTS ----------------
    def display_results(self, devices):
        """Display scan results in a formatted way"""
        if not devices:
            print("\n❌ No devices found!")
            return
            
        print("\n📊 SCAN RESULTS")
        print("=" * 80)
        
        # Sort by IP
        devices.sort(key=lambda d: [int(octet) for octet in d["ip"].split(".")])
        
        for i, device in enumerate(devices, 1):
            print(f"\n{i}. {device['ip']}")
            print(f"   Type: {device['type']}")
            print(f"   Hostname: {device['hostname']}")
            print(f"   MAC: {device['mac']}")
            print(f"   Detected via: {', '.join(device['detection_methods'])}")
            
            # Display open ports
            if device['open_ports']:
                print(f"   📡 Open Ports ({len(device['open_ports'])}):")
                for port, service in sorted(device['open_ports'].items()):
                    banner = device['banners'].get(port)
                    if banner:
                        print(f"      {port:<5} {service:<15} | Banner: {banner[:50]}...")
                    else:
                        print(f"      {port:<5} {service}")
            else:
                print("   📡 Open Ports: None")
                
        print("\n" + "=" * 80)
        print(f"📈 SUMMARY: Found {len(devices)} device(s)")
        
        # Count by type
        type_count = {}
        for device in devices:
            type_count[device['type']] = type_count.get(device['type'], 0) + 1
            
        print("Device types:")
        for dev_type, count in type_count.items():
            print(f"  {dev_type}: {count}")
            
        print("=" * 80)


# ---------------- PUBLIC INTERFACE ----------------
def discover_devices(scan_ports=False, port_scan_type="quick"):
    """
    Public function to discover devices on the network.
    
    Args:
        scan_ports (bool): Whether to scan for open ports
        port_scan_type (str): 'quick', 'common', or 'all'
        
    Returns:
        list: List of device dictionaries
    """
    try:
        scanner = EnhancedNetworkScanner()
        return scanner.scan_all_devices(
            scan_ports=scan_ports,
            port_scan_type=port_scan_type
        )
    except Exception as e:
        print(f"❌ Error during scan: {e}")
        return []


def scan_and_display(scan_ports=True, port_scan_type="common"):
    """Complete scan with display"""
    scanner = EnhancedNetworkScanner()
    devices = scanner.scan_all_devices(
        scan_ports=scan_ports,
        port_scan_type=port_scan_type
    )
    scanner.display_results(devices)
    return devices


# ---------------- MAIN EXECUTION ----------------
if __name__ == "__main__":
    # Run standalone scanner
    print("🔧 Enhanced Network Scanner")
    print("=" * 40)
    
    # Example usage
    devices = scan_and_display(
        scan_ports=True,
        port_scan_type="common"  # quick | common | all
    )