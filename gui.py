import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import report_gen
import wifi_scanner
import mac_spoofer
import dos_detector

attack_count = 0

def run_scanner():
    Thread(target=wifi_scanner.scan_wifi).start()

def run_mac_detector():
    Thread(target=mac_spoofer.start_detection).start()

def run_dos_detector():
    def alert(packet):
        global attack_count
        attack_count += 1
        dos_status_label.config(text=f"Deauth Attacks Detected: {attack_count}")

    Thread(target=dos_detector.start_detection, args=("wlp4s0", alert)).start()

def show_report():
    report = report_gen.read_report()
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.INSERT, report)

root = tk.Tk()
root.title("WiScan - Wireless IDS")
root.geometry("600x450")

tk.Button(root, text="Scan Wi-Fi", command=run_scanner).pack(pady=5)
tk.Button(root, text="Start MAC Spoofing Detector", command=run_mac_detector).pack(pady=5)
tk.Button(root, text="Start Deauth Detector", command=run_dos_detector).pack(pady=5)

dos_status_label = tk.Label(root, text="Deauth Attacks Detected: 0", font=("Helvetica", 12))
dos_status_label.pack(pady=5)

tk.Button(root, text="View Report", command=show_report).pack(pady=5)

text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=10)
text_area.pack(pady=10)

root.mainloop()
