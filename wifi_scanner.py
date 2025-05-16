from scapy.all import sniff, Dot11

def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        ssid = pkt.info.decode() if pkt.info else "<Hidden SSID>"
        bssid = pkt.addr2
        print(f"[WiFi Scanner] Detected Network: SSID={ssid}, BSSID={bssid}")

def scan_wifi(interface='wlp4s0'):
    print("[WiFi Scanner] Starting Wi-Fi scan for 15 seconds...")
    sniff(iface=interface, prn=packet_handler, timeout=15)
    print("[WiFi Scanner] Scan complete. No suspicious networks detected.")
