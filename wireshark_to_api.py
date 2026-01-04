#!/usr/bin/env python3
"""
Wireshark PCAP to IoT Attack Detector API
Simple script to analyze network traffic captures for attacks.

Usage:
    python wireshark_to_api.py <pcap_file>
    
Example:
    python wireshark_to_api.py captured_traffic.pcap
"""

import sys
import requests
import json
from collections import defaultdict

# Try to import scapy
try:
    from scapy.all import rdpcap, TCP, UDP, IP
except ImportError:
    print("❌ Scapy not installed. Run: pip install scapy")
    sys.exit(1)

# API Configuration
API_URL = "http://localhost:8000"


def extract_flow_features(pcap_file):
    """
    Extract network flow features from a PCAP file.
    Groups packets into flows and calculates statistics.
    """
    print(f"📂 Reading PCAP file: {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"❌ File not found: {pcap_file}")
        return []
    except Exception as e:
        print(f"❌ Error reading PCAP: {e}")
        return []
    
    print(f"📦 Found {len(packets)} packets")
    
    # Group packets into flows (by src_ip, dst_ip, src_port, dst_port, protocol)
    flows = defaultdict(lambda: {
        'packets': [],
        'fwd_packets': [],
        'bwd_packets': [],
        'start_time': None,
        'end_time': None
    })
    
    for pkt in packets:
        if IP not in pkt:
            continue
            
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Get ports
        src_port = 0
        dst_port = 0
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        
        # Create flow key (bidirectional)
        flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
        
        # Determine direction
        is_forward = (src_ip, src_port) <= (dst_ip, dst_port)
        
        flow = flows[flow_key]
        flow['packets'].append(pkt)
        
        if is_forward:
            flow['fwd_packets'].append(pkt)
        else:
            flow['bwd_packets'].append(pkt)
        
        # Track timing
        pkt_time = float(pkt.time)
        if flow['start_time'] is None:
            flow['start_time'] = pkt_time
        flow['end_time'] = pkt_time
    
    print(f"🔗 Found {len(flows)} unique flows")
    
    # Calculate features for each flow
    flow_features = []
    for flow_key, flow_data in flows.items():
        features = calculate_flow_features(flow_data)
        flow_features.append(features)
    
    return flow_features


def calculate_flow_features(flow_data):
    """
    Calculate CICIDS-compatible features from flow data.
    """
    fwd_packets = flow_data['fwd_packets']
    bwd_packets = flow_data['bwd_packets']
    all_packets = flow_data['packets']
    
    # Basic counts
    total_fwd = len(fwd_packets)
    total_bwd = len(bwd_packets)
    
    # Packet lengths
    fwd_lengths = [len(p) for p in fwd_packets] if fwd_packets else [0]
    bwd_lengths = [len(p) for p in bwd_packets] if bwd_packets else [0]
    all_lengths = [len(p) for p in all_packets] if all_packets else [0]
    
    # Duration
    duration = flow_data['end_time'] - flow_data['start_time'] if flow_data['start_time'] else 0
    duration_us = max(duration * 1000000, 1)  # Microseconds, minimum 1
    
    # Inter-arrival times
    fwd_iats = calculate_iats(fwd_packets)
    bwd_iats = calculate_iats(bwd_packets)
    flow_iats = calculate_iats(all_packets)
    
    # TCP Flags
    flags = count_tcp_flags(all_packets)
    
    # Build feature dictionary matching your model's expected format
    features = {
        "Flow Duration": duration_us,
        "Total Fwd Packets": total_fwd,
        "Total Backward Packets": total_bwd,
        "Total Length of Fwd Packets": sum(fwd_lengths),
        "Total Length of Bwd Packets": sum(bwd_lengths),
        "Fwd Packet Length Max": max(fwd_lengths),
        "Fwd Packet Length Min": min(fwd_lengths),
        "Fwd Packet Length Mean": sum(fwd_lengths) / len(fwd_lengths),
        "Fwd Packet Length Std": std_dev(fwd_lengths),
        "Bwd Packet Length Max": max(bwd_lengths),
        "Bwd Packet Length Min": min(bwd_lengths),
        "Bwd Packet Length Mean": sum(bwd_lengths) / len(bwd_lengths),
        "Bwd Packet Length Std": std_dev(bwd_lengths),
        "Flow Bytes/s": sum(all_lengths) / duration if duration > 0 else 0,
        "Flow Packets/s": len(all_packets) / duration if duration > 0 else 0,
        "Flow IAT Mean": sum(flow_iats) / len(flow_iats) if flow_iats else 0,
        "Flow IAT Std": std_dev(flow_iats),
        "Fwd IAT Total": sum(fwd_iats),
        "Fwd IAT Mean": sum(fwd_iats) / len(fwd_iats) if fwd_iats else 0,
        "Fwd IAT Std": std_dev(fwd_iats),
        "Fwd IAT Max": max(fwd_iats) if fwd_iats else 0,
        "Fwd IAT Min": min(fwd_iats) if fwd_iats else 0,
        "Bwd IAT Total": sum(bwd_iats),
        "Bwd IAT Mean": sum(bwd_iats) / len(bwd_iats) if bwd_iats else 0,
        "Bwd IAT Std": std_dev(bwd_iats),
        "Fwd PSH Flags": 0,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Bwd URG Flags": 0,
        "Fwd Header Length": 20 * total_fwd,
        "Bwd Header Length": 20 * total_bwd,
        "Fwd Packets/s": total_fwd / duration if duration > 0 else 0,
        "Bwd Packets/s": total_bwd / duration if duration > 0 else 0,
        "Min Packet Length": min(all_lengths),
        "Max Packet Length": max(all_lengths),
        "Packet Length Mean": sum(all_lengths) / len(all_lengths),
        "Packet Length Std": std_dev(all_lengths),
        "Packet Length Variance": std_dev(all_lengths) ** 2,
        "FIN Flag Count": flags['FIN'],
        "SYN Flag Count": flags['SYN'],
        "RST Flag Count": flags['RST'],
        "PSH Flag Count": flags['PSH'],
        "ACK Flag Count": flags['ACK'],
        "URG Flag Count": flags['URG'],
        "CWE Flag Count": flags['CWR'],
        "ECE Flag Count": flags['ECE'],
        "Down/Up Ratio": total_bwd / total_fwd if total_fwd > 0 else 0,
        "Average Packet Size": sum(all_lengths) / len(all_lengths),
        "Avg Fwd Segment Size": sum(fwd_lengths) / len(fwd_lengths),
        "Avg Bwd Segment Size": sum(bwd_lengths) / len(bwd_lengths),
        "Fwd Header Length.1": 20 * total_fwd,
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": total_fwd,
        "Subflow Fwd Bytes": sum(fwd_lengths),
        "Subflow Bwd Packets": total_bwd,
        "Subflow Bwd Bytes": sum(bwd_lengths)
    }
    
    return features


def calculate_iats(packets):
    """Calculate inter-arrival times between packets."""
    if len(packets) < 2:
        return []
    
    iats = []
    for i in range(1, len(packets)):
        iat = float(packets[i].time) - float(packets[i-1].time)
        iats.append(iat * 1000000)  # Convert to microseconds
    return iats


def std_dev(values):
    """Calculate standard deviation."""
    if len(values) < 2:
        return 0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return variance ** 0.5


def count_tcp_flags(packets):
    """Count TCP flags in packets."""
    flags = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'CWR': 0, 'ECE': 0}
    
    for pkt in packets:
        if TCP in pkt:
            tcp = pkt[TCP]
            if tcp.flags.F: flags['FIN'] += 1
            if tcp.flags.S: flags['SYN'] += 1
            if tcp.flags.R: flags['RST'] += 1
            if tcp.flags.P: flags['PSH'] += 1
            if tcp.flags.A: flags['ACK'] += 1
            if tcp.flags.U: flags['URG'] += 1
    
    return flags


def send_to_api(flow_features):
    """Send flow features to the API for prediction."""
    print(f"\n🚀 Sending {len(flow_features)} flows to API...")
    
    # Check if API is running
    try:
        health = requests.get(f"{API_URL}/health", timeout=5)
        if health.status_code != 200:
            print("❌ API health check failed")
            return
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to API. Make sure to run: python api.py")
        return
    
    # Send flows for prediction
    results = []
    attacks_detected = 0
    
    for i, features in enumerate(flow_features, 1):
        try:
            response = requests.post(
                f"{API_URL}/predict",
                json={"features": features},
                timeout=10
            )
            result = response.json()
            results.append(result)
            
            # Display result
            if result.get('is_attack', False):
                attacks_detected += 1
                print(f"  ⚠️  Flow {i}: ATTACK - {result.get('prediction', 'Unknown')} "
                      f"(Confidence: {result.get('confidence', 'N/A')})")
            else:
                print(f"  ✅ Flow {i}: Benign "
                      f"(Confidence: {result.get('confidence', 'N/A')})")
                
        except Exception as e:
            print(f"  ❌ Flow {i}: Error - {e}")
    
    # Summary
    print("\n" + "="*50)
    print("📊 SUMMARY")
    print("="*50)
    print(f"  Total flows analyzed: {len(flow_features)}")
    print(f"  Attacks detected: {attacks_detected}")
    print(f"  Benign flows: {len(flow_features) - attacks_detected}")
    
    if attacks_detected > 0:
        print(f"\n  ⚠️  ALERT: {attacks_detected} potential attacks detected!")
    else:
        print(f"\n  ✅ No attacks detected in this capture.")


def main():
    """Main entry point."""
    print("="*50)
    print("🦈 Wireshark to IoT Attack Detector")
    print("="*50)
    
    # Check command line arguments
    if len(sys.argv) < 2:
        print("\nUsage: python wireshark_to_api.py <pcap_file>")
        print("\nExample:")
        print("  python wireshark_to_api.py captured_traffic.pcap")
        print("\nTo capture traffic first:")
        print("  sudo tshark -i eth0 -c 100 -w traffic.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Extract features from PCAP
    flow_features = extract_flow_features(pcap_file)
    
    if not flow_features:
        print("❌ No flows extracted from PCAP file")
        sys.exit(1)
    
    # Send to API
    send_to_api(flow_features)


if __name__ == "__main__":
    main()
