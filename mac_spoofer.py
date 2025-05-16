from scapy.all import sniff, ARP

interface = 'wlp4s0'

def detect_spoof(pkt):
    if pkt.haslayer(ARP):
        sender_mac = pkt[ARP].hwsrc
        sender_ip = pkt[ARP].psrc
        print(f"[MAC Spoofer] ARP Packet: IP={sender_ip}, MAC={sender_mac}")
        print("[MAC Spoofer] ALERT! Possible MAC spoofing detected!")

def start_detection():
    print("[MAC Spoofer] Starting ARP monitoring for MAC spoofing...")
    sniff(iface=interface, filter="arp", prn=detect_spoof, store=0)
    print("[MAC Spoofer] MAC spoofing detection stopped.")
    if __name__ == "__main__":
        try:
            print("[MAC Spoofer] Press Ctrl+C to stop monitoring at any time.")
            start_detection()
        except KeyboardInterrupt:
            print("\n[MAC Spoofer] Monitoring interrupted by user. Exiting...")