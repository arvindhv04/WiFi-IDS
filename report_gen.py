
from datetime import datetime

def log_alert(alert_type, details):
    with open("wids_alerts.log", "a") as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"[{timestamp}] {alert_type}: {details}\n")

def read_report():
    try:
        with open("wids_alerts.log", "r") as f:
            return f.read()
    except FileNotFoundError:
        return "No alerts logged yet."

if __name__ == "__main__":
    print(read_report())
