# Network Intrusion Detection System (NIDS)

## 📌 Overview

`capture.py` is a Python-based tool that utilizes the **Scapy** library to sniff network traffic across all available interfaces. It processes packets through three main stages:

1. **Capture**: Converts raw packets into a structured JSON format.
2. **Feature Extraction**: Aggregates packet data per Source IP to identify behavioral patterns.
3. **Alerting**: Matches behavior against security thresholds to detect attacks like Port Scanning, Flooding, and MQTT abuse.

---

## 🚀 Features

* **Real-time Sniffing**: Captures traffic on all active network interfaces.
* **Protocol Analysis**: Supports Ethernet, IP, TCP, UDP, and ICMP.
* **IoT Aware**: Specialized logic to extract **MQTT topics** and calculate publishing rates.
* **Security Rules**: Detects the following anomalies:
* **Port Scanning**: High number of unique destination ports.
* **Flood Attacks**: Excessive packet volume.
* **SYN Flooding**: High ratio of TCP SYN packets.
* **DNS Anomalies**: Excessive queries to port 53.
* **MQTT Abuse**: Excessive unique topics or high message frequency.



---

## 🛠 Prerequisites

You must have Python installed along with the following library:

```bash
pip install scapy

```

*Note: Network sniffing usually requires **root/administrator** privileges.*

---

## 📂 Output Files

The script generates three main log files:

* `Total_packets_log.pcap`: The raw packet data for deep forensic analysis.
* `packets.jsonl`: A line-delimited JSON file containing individual packet attributes.
* `feature.jsonl`: Aggregated statistics grouped by the Source IP.
* `alerts.jsonl`: Security alerts triggered by the detection engine.

---

## 🖥 How to Use

1. **Run the script**:
```bash
sudo python capture.py

```


2. **View Alerts**: Monitor the `alerts.jsonl` file to see detected threats in real-time.
3. **Evidence Extraction**: Once the capture stops, the script automatically triggers `extract_evidence.py` (if available) to compile forensic data.

---

## ⚠️ Configuration

You can customize the detection sensitivity by modifying the **thresholds** inside the `rules()` function:

* `PORT_SCAN_THRESHOLD`: Number of ports before flagging a scan.
* `FLOOD_PKT_THRESHHOLD`: Packet count limit per source.
* `MQTT_RATE_THRESHOLD`: Maximum allowed MQTT messages per minute.

Would you like me to help you refine the **deduplication logic** in the advanced alert function?

