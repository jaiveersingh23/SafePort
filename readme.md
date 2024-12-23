# SafePort - Dynamic Firewall for IoT Devices

## Overview
SafePort is a dynamic firewall system designed to secure IoT devices. It combines real-time traffic monitoring, machine learning anomaly detection, and integration with a threat intelligence database (AbuseIPDB). This system monitors network traffic, detects anomalies, and automatically blocks malicious IPs.

## Features
- **Real-Time Traffic Monitoring**: Capture network packets using Scapy.
- **Machine Learning Anomaly Detection**: Use Isolation Forest to detect unusual communication patterns.
- **Web Dashboard**: Visualize device activity, blocked traffic, and malicious IPs.
- **Threat Database Integration**: Fetch and block known malicious IPs from AbuseIPDB.

## Requirements
- Python 3.x
- Libraries:
    - `scapy`
    - `abuseipdb`
    - `flask`
    - `sklearn`
    - `pandas`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/SafePort.git
   cd SafePort
