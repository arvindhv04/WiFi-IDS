from scapy.all import sniff, Dot11Deauth

def start_detection(interface, alert_callback):
    def detect_deauth(packet):
        if packet.haslayer(Dot11Deauth):
            alert_callback(packet)

    sniff(iface=interface, prn=detect_deauth, store=0)
    print("[Deauth Detector] Starting Deauth detection...")
    print("[Deauth Detector] Deauth detection stopped.")