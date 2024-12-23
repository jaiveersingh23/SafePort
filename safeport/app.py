import scapy.all as scapy
import json
import time
import pandas as pd
from sklearn.ensemble import IsolationForest
from flask import Flask, render_template
from datetime import datetime
from abuseipdb import AbuseIPDB

# Initialize Flask app
app = Flask(__name__)

# Initialize the AI model for anomaly detection
model = IsolationForest(contamination=0.1)  # 10% of the data is considered anomalous

# Device communication logs
device_logs = {
    "device_1": ["192.168.0.101", "192.168.0.102"],
    "device_2": ["192.168.0.103"],
}

# Threat detection
MALICIOUS_IPS = set()

# Function to simulate IoT traffic based on logs
def simulate_traffic():
    traffic_data = []
    for device_id, ips in device_logs.items():
        for ip in ips:
            traffic_data.append([device_id, ip, datetime.now()])
    return traffic_data

# Real-time traffic capture with scapy
def packet_sniffer():
    print("Sniffing packets...")
    scapy.sniff(prn=process_packet, store=0, timeout=30)  # Timeout after 30 seconds

# Processing each captured packet
def process_packet(packet):
    ip_src = packet[scapy.IP].src
    ip_dst = packet[scapy.IP].dst
    print(f"Packet captured: {ip_src} -> {ip_dst}")
    if ip_dst in MALICIOUS_IPS:
        print(f"Blocked packet: {ip_src} -> {ip_dst} (Malicious IP)")
    else:
        traffic_data = simulate_traffic()
        check_for_anomalies(traffic_data)

# Machine learning anomaly detection
def check_for_anomalies(traffic_data):
    df = pd.DataFrame(traffic_data, columns=["device_id", "ip_address", "timestamp"])
    features = pd.get_dummies(df["ip_address"])  # One-hot encoding of IP addresses
    predictions = model.fit_predict(features)
    anomalies = df[predictions == -1]
    if not anomalies.empty:
        print(f"Anomalous traffic detected: {anomalies}")

# Threat Database integration
def update_malicious_ips():
    api_key = "YOUR_ABUSEIPDB_API_KEY"  # Get from AbuseIPDB
    abuse_ip_db = AbuseIPDB(api_key)
    report = abuse_ip_db.get_report()
    for entry in report["data"]:
        MALICIOUS_IPS.add(entry["ipAddress"])

# Web Dashboard for Monitoring
@app.route('/')
def dashboard():
    return render_template("dashboard.html", logs=device_logs, malicious_ips=MALICIOUS_IPS)

if __name__ == "__main__":
    update_malicious_ips()  # Update malicious IPs on startup
    packet_sniffer()  # Start sniffing packets
    app.run(debug=True)  # Start Flask web app
