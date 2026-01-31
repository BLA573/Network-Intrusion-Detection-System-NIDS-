# capture.py

import json
import time
import subprocess

from collections import defaultdict
from scapy.all import Ether, IP, TCP, UDP, rdpcap, sniff, get_if_list, wrpcap, get_if_list 

FOLDER = "packets.jsonl"        # raw packet-level features
OUT_FOLDER = "feature.jsonl"    # aggregated per-source features
PCAP_LOG = "Total_packets_log.pcap"  # full PCAP dump
OUT_FILE = "packets.jsonl"
Proto_map =  {1: "ICMP", 17: "UDP", 6: "TCP"}  # Maps IP protocole numbers with thire corosponding readeble format


# --- Converts one Scapy packet to JSON-format ---
def pkt_to_dict(pkt):
    d = {}
    d['time'] = float(pkt.time) if hasattr(pkt, 'time') else None

    # Ethernet
    if Ether in pkt:
        #eth = pkt[Ether]
        d['eth_src'] = pkt[Ether].src
        d['eth_dst'] = pkt[Ether].dst

    # IP
    if IP in pkt:
        ip = pkt[IP]
        d['src'] = ip.src
        d['dst_ip'] = ip.dst
        d['proto'] = Proto_map.get(ip.proto, str(ip.proto))

    # TCP
    if TCP in pkt:
        tcp = pkt[TCP]
        d['src_port'] = int(tcp.sport)
        d['dst_port'] = int(tcp.dport)
        d['flags'] = str(tcp.flags)
        # payload length
        d['payload_len'] = len(bytes(tcp.payload))
        if pkt[TCP].dport == 1883:
            raw = bytes(pkt[TCP].payload)
            if raw :
                try:
                    txt = raw.decode('utf-8' , errors='ignore')
                    if "TOPIC:" in txt:
                        start = txt.find("TOPIC:") + len ("TOPIC:")
                        end = txt.find(";" , start)
                        if end == -1:
                            end = len(txt)
                        topic = txt[start:end].strip()
                        if topic:
                            d["mqtt_topic"] = topic

                except Exception:
                    pass
    # UDP
    if UDP in pkt:
        udp = pkt[UDP]
        d['src_port'] = int(udp.sport)
        d['dst_port'] = int(udp.dport)
        d['payload_len'] = len(bytes(udp.payload))

    # ---- total length if available ---
    try:
        d['len'] = int(pkt.len)
    except Exception:
        pass
    return d

paket_counter = 0  # Global packet index
def main(pkt):
    global paket_counter
    print("[+] capturing all packages on all interface ...")
    # --- Writing log files ---
    with open(PCAP_LOG, "a") as f:
        wrpcap(PCAP_LOG, pkt, append=True) 
    # --- Writes one JSON line per packet     
    with open(OUT_FILE, "a+") as f:
        for p in pkt:
            obj = pkt_to_dict(p)
            obj["pkt_index"] = paket_counter
            f.write(json.dumps(obj) + "\n")
    paket_counter += 1
    print("[+] Wrote", OUT_FILE, "with", len(pkt), "entries")
 

# --- Filter and write featcher.js with each ip ---
def pakets_format():
    least_pkt_index = defaultdict(int)
    count = defaultdict(int)
    ds_port = defaultdict(set)
    Protocol = defaultdict(set)
    syn_count = defaultdict(int)
    dns_queries = defaultdict(int)
    total_len = defaultdict(int)
    mqtt_topics = defaultdict(set)
    mqtt_publish_count = defaultdict(int)
    mqtt_first_ts = defaultdict(lambda: None)
    mqtt_last_ts = defaultdict(lambda: None)
    with open(FOLDER, 'r') as f:
        for line in f:
            try:
                packet = json.loads(line) 
                src = packet.get("src", None)
                dport = packet.get("dst_port", None)
                Proto = packet.get("proto",None)
                syn = packet.get ("flags", "")
                dns_queries_count = packet.get("dst_port", None)
                length = packet.get("len", 0)
                topic = packet.get("mqtt_topic", None)
                ts = packet.get("time", None)
                pkt_index = packet.get("pkt_index", None)
                if src and pkt_index is not None:
                    least_pkt_index[src] = pkt_index
                if src:          
                    count[src] += 1
                    if dport:
                        ds_port[src].add(dport)
                    if Proto:
                        Protocol[src].add(Proto)
                    if src and "S" in syn:
                        syn_count[src] += 1
                    if dns_queries_count == 53:
                        dns_queries[src] += 1
                 
                    if topic:
                        mqtt_topics[src].add(topic)
                        mqtt_publish_count[src] += 1
                        if ts is not None:
                            if mqtt_first_ts[src] is None or ts < mqtt_first_ts[src]:
                                mqtt_first_ts[src] = ts
                            if mqtt_last_ts[src] is None or ts > mqtt_last_ts[src]: 
                                mqtt_last_ts[src] = ts

                    total_len[src] += length
                        
            except json.JSONDecodeError:
                continue
    with open(OUT_FOLDER, 'w') as f:
        for src in count:
            avg_len = total_len[src] / count[src] if count[src] else 0

            pub_count = mqtt_publish_count[src]
            if pub_count > 0 and mqtt_first_ts[src] is not None and mqtt_last_ts[src] is not None:
                duration_seconds = max(1.0, mqtt_last_ts[src] - mqtt_first_ts[src])
                duration_minutes = max(1.0, duration_seconds / 60.0)  # avoid division by <1 minute
                publish_rate = pub_count / duration_minutes
            else:
                publish_rate = 0.0
            features = {
                "src" : src,
                "Packet_count" : count[src],
                "Protocol" : list(Protocol[src]),
                "unique_dst_ports" : len(ds_port[src]),
                "syn_count" : syn_count[src],
                "dns_queries_count" : dns_queries[src],
                "avg_pkt_size" : avg_len,
                "mqtt_publish_count": pub_count,
                "mqtt_unique_topics": len(mqtt_topics[src]),
                "mqtt_publish_rate_per_min": round(publish_rate, 2),
                "pkt_index" : least_pkt_index[src]

            }
            f.write(json.dumps(features) + "\n")


# --- Write alarts for every packet --- 

def rules():
    FOLDER = "feature.jsonl"
    OUT_FOLDER = "alerts.jsonl"
    alerts = []

    with open(FOLDER, 'r') as f:
        for line in f:
            fetchs = json.loads(line)
            pkt_index = fetchs.get("pkt_index")
            src = fetchs["src"]
            pkt_count = fetchs["Packet_count"]
            uniq_ports = fetchs["unique_dst_ports"]
            syn_count = fetchs["syn_count"]
            dns_queries = fetchs["dns_queries_count"]
            avg_len = fetchs['avg_pkt_size']
            mqtt_unique_topics = fetchs.get("mqtt_unique_topics", 0)
            mqtt_rate = fetchs.get("mqtt_publish_rate_per_min", 0.0)


      #...adjustr your thrushold  here.....
            MQTT_TOPICS_THRESHOLD = 20
            MQTT_RATE_THRESHOLD = 30.0
            PORT_SCAN_THRESHOLD = 20
            FLOOD_PKT_THRESHHOLD = 100
            SYN_RATIO_THRUSHOLD = 20
            SYN_ABS_THRUSHOLD = 20
            DNS_QUERIES_THRUSHOLD = 50
            LARGE_PKT_AVG = 1200
            TINY_PKT_AVG = 60
            DEDUP_SECONDS = 60

            if uniq_ports > PORT_SCAN_THRESHOLD:
                alerts.append({
                    "src" : src,
                    "alert" : "PORT SCAN",
                    "severity":"Medium",
                    "detail" : f"connected {uniq_ports} different ports",
                    "evidence": pkt_index
                })
            if pkt_count > FLOOD_PKT_THRESHHOLD:
                alerts.append({
                    "src" : fetchs["src"],
                    "alert" : "FLOOD",
                    "severity":"HIGH",
                    "detail" : f"sent {pkt_count} number of pakets",
                    "evidence": pkt_index
                })
            if pkt_count > 0 and (syn_count / pkt_count) > 0.5 and syn_count > SYN_RATIO_THRUSHOLD:
                alerts.append({
                    "src" : fetchs["src"],
                    "alert" : " SYN FLOOD",
                    "severity":"HIGH",
                    "detail" : f"sent {syn_count} numbers of SYN pakets",
                    "evidence": pkt_index
                })
            if dns_queries > DNS_QUERIES_THRUSHOLD:
                alerts.append({
                    "src" : fetchs["src"],
                    "alert" : "suspicions DNS queries",
                    "severity":"Medium",
                    "detail" : f"sent {dns_queries}  suspicions DNS queries",
                    "evidence": pkt_index
                })    
            if avg_len > LARGE_PKT_AVG:
                alerts.append({
                    "src" : fetchs["src"],
                    "alert" : "LARGE_PKT",
                    "severity":"Low",
                    "detail" : f"avg size {avg_len:.1f}",
                    "evidence": pkt_index
                })
            if mqtt_unique_topics > MQTT_TOPICS_THRESHOLD:
                alerts.append({
                    "src": src, 
                    "alert": "MQTT_ABUSE_TOPICS", 
                    "severity":"HIGH",
                    "detail": f"{mqtt_unique_topics} unique topics",
                    "evidence": pkt_index
                })
            if mqtt_rate > MQTT_RATE_THRESHOLD:
                alerts.append({
                    "src": src,
                    "alert": "MQTT_ABUSE_RATE",
                    "severity":"HIGH", 
                    "detail": f"{mqtt_rate} msgs/min",
                    "evidence": pkt_index
                })
            if mqtt_unique_topics > MQTT_TOPICS_THRESHOLD and dns_queries > 20:
                alerts.append({
                     "src": src,
                     "severity":"HIGH",
                     "detail": f"both mqtt_unique_topics  and  dns_queries  are above treshold",
                     "evidence": pkt_index
                })



# Advanced write alart function (need modefication)

    # recent_alerts = {}
    # def write_alerts(alerts):
    #     """Append alert dict to ALERT_FILE and update dedup store."""
    #     for alert in alerts:
    #         key = (alert.get("src"), alert.get("alerts"))
    #         last = recent_alerts.get(key)
    #         now = time.time()
    #         if last and (now - last) < DEDUP_SECONDS:
    #             return  # skip duplicate alerts within dedup window
    #     # record time and write
    #         alert["time"] = now
    #         recent_alerts[key] = now
    #     with open(OUT_FOLDER, "a") as f:
    #         f.write(json.dumps(alerts) + "\n")
    #     for line in alerts:
    #          print("alerts:", alerts[line], "-", alerts.get("detail", ""), "Total")


    with open(OUT_FOLDER, 'w') as f:
        print("[+] Running rules on", FOLDER )
        for line in range(len(alerts)):
            f.write(json.dumps(alerts[line]) + "\n")
        f.write(json.dumps(len(alerts)) + " Total alerts")
    print(f"[+] wrote {OUT_FOLDER} with {len(alerts)} alerts")


if __name__ == "__main__":
    def on_packet(pkt):
        main([pkt])
        print("[+] specifing each pakets featuer....")
        pakets_format()
        print("[+] Cheking for any attakes....")
        rules()
    pkt_if = get_if_list()
    pkt = sniff(iface= pkt_if,  prn= on_packet, store=False )

    subprocess.run(["python", "extract_evidence.py"])






