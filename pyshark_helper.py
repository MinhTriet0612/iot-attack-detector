"""
PyShark Helper Module
Trích xuất flow features từ file PCAP sử dụng PyShark.
"""

import pyshark
from collections import defaultdict
from typing import Dict, List, Any
import statistics


def extract_flows_from_pcap(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Đọc file PCAP và trích xuất các flow features.
    
    Args:
        pcap_path: Đường dẫn tới file PCAP
        
    Returns:
        Danh sách các flow features dictionary
    """
    # Đọc file PCAP
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    
    # Nhóm packets theo flow (5-tuple)
    flows = defaultdict(lambda: {
        'packets': [],
        'fwd_lengths': [],
        'bwd_lengths': [],
        'fwd_times': [],
        'bwd_times': [],
        'flags': defaultdict(int),
        'start_time': None,
        'end_time': None,
    })
    
    try:
        for pkt in cap:
            try:
                # Chỉ xử lý IP packets
                if not hasattr(pkt, 'ip'):
                    continue
                
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                protocol = int(pkt.ip.proto)
                
                # Lấy ports nếu có
                src_port = 0
                dst_port = 0
                
                if hasattr(pkt, 'tcp'):
                    src_port = int(pkt.tcp.srcport)
                    dst_port = int(pkt.tcp.dstport)
                    # Đếm TCP flags
                    if hasattr(pkt.tcp, 'flags'):
                        flags_hex = int(pkt.tcp.flags, 16)
                        if flags_hex & 0x01: flows[flow_key]['flags']['FIN'] += 1
                        if flags_hex & 0x02: flows[flow_key]['flags']['SYN'] += 1
                        if flags_hex & 0x04: flows[flow_key]['flags']['RST'] += 1
                        if flags_hex & 0x08: flows[flow_key]['flags']['PSH'] += 1
                        if flags_hex & 0x10: flows[flow_key]['flags']['ACK'] += 1
                        if flags_hex & 0x20: flows[flow_key]['flags']['URG'] += 1
                elif hasattr(pkt, 'udp'):
                    src_port = int(pkt.udp.srcport)
                    dst_port = int(pkt.udp.dstport)
                
                # Tạo flow key (bidirectional)
                flow_key = tuple(sorted([
                    (src_ip, src_port),
                    (dst_ip, dst_port)
                ]))
                
                # Xác định hướng
                is_forward = (src_ip, src_port) <= (dst_ip, dst_port)
                
                # Lấy thời gian và kích thước
                pkt_time = float(pkt.sniff_timestamp)
                pkt_len = int(pkt.length)
                
                flow = flows[flow_key]
                flow['protocol'] = protocol
                
                if is_forward:
                    flow['fwd_lengths'].append(pkt_len)
                    flow['fwd_times'].append(pkt_time)
                else:
                    flow['bwd_lengths'].append(pkt_len)
                    flow['bwd_times'].append(pkt_time)
                
                # Track timing
                if flow['start_time'] is None:
                    flow['start_time'] = pkt_time
                flow['end_time'] = pkt_time
                
            except Exception:
                continue
                
    finally:
        cap.close()
    
    # Chuyển đổi sang features
    flow_features = []
    for flow_key, flow_data in flows.items():
        features = calculate_features(flow_data)
        flow_features.append(features)
    
    return flow_features


def calculate_features(flow_data: Dict) -> Dict[str, Any]:
    """Tính toán CICIDS-style features từ flow data."""
    
    fwd_lengths = flow_data['fwd_lengths'] or [0]
    bwd_lengths = flow_data['bwd_lengths'] or [0]
    all_lengths = fwd_lengths + bwd_lengths
    
    fwd_times = flow_data['fwd_times']
    bwd_times = flow_data['bwd_times']
    
    # Duration
    duration = (flow_data['end_time'] - flow_data['start_time']) if flow_data['start_time'] else 0
    duration_us = max(duration * 1000000, 1)
    
    # IAT calculations
    fwd_iats = calculate_iats(fwd_times)
    bwd_iats = calculate_iats(bwd_times)
    all_times = sorted(fwd_times + bwd_times)
    flow_iats = calculate_iats(all_times)
    
    flags = flow_data['flags']
    
    return {
        "Protocol": flow_data.get('protocol', 6),
        "Flow Duration": duration_us,
        "Tot Fwd Pkts": len(fwd_lengths),
        "Tot Bwd Pkts": len(bwd_lengths),
        "TotLen Fwd Pkts": sum(fwd_lengths),
        "TotLen Bwd Pkts": sum(bwd_lengths),
        "Fwd Pkt Len Max": max(fwd_lengths),
        "Fwd Pkt Len Min": min(fwd_lengths),
        "Fwd Pkt Len Mean": safe_mean(fwd_lengths),
        "Fwd Pkt Len Std": safe_stdev(fwd_lengths),
        "Bwd Pkt Len Max": max(bwd_lengths),
        "Bwd Pkt Len Min": min(bwd_lengths),
        "Bwd Pkt Len Mean": safe_mean(bwd_lengths),
        "Bwd Pkt Len Std": safe_stdev(bwd_lengths),
        "Flow Byts/s": sum(all_lengths) / duration if duration > 0 else 0,
        "Flow Pkts/s": len(all_lengths) / duration if duration > 0 else 0,
        "Flow IAT Mean": safe_mean(flow_iats) * 1000000,
        "Flow IAT Std": safe_stdev(flow_iats) * 1000000,
        "Fwd IAT Tot": sum(fwd_iats) * 1000000,
        "Fwd IAT Mean": safe_mean(fwd_iats) * 1000000,
        "Fwd IAT Std": safe_stdev(fwd_iats) * 1000000,
        "Fwd IAT Max": max(fwd_iats) * 1000000 if fwd_iats else 0,
        "Fwd IAT Min": min(fwd_iats) * 1000000 if fwd_iats else 0,
        "Bwd IAT Tot": sum(bwd_iats) * 1000000,
        "Bwd IAT Mean": safe_mean(bwd_iats) * 1000000,
        "Bwd IAT Std": safe_stdev(bwd_iats) * 1000000,
        "Fwd PSH Flags": flags.get('PSH', 0),
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": flags.get('URG', 0),
        "Bwd URG Flags": 0,
        "Fwd Header Len": 20 * len(fwd_lengths),
        "Bwd Header Len": 20 * len(bwd_lengths),
        "Fwd Pkts/s": len(fwd_lengths) / duration if duration > 0 else 0,
        "Bwd Pkts/s": len(bwd_lengths) / duration if duration > 0 else 0,
        "Pkt Len Min": min(all_lengths),
        "Pkt Len Max": max(all_lengths),
        "Pkt Len Mean": safe_mean(all_lengths),
        "Pkt Len Std": safe_stdev(all_lengths),
        "Pkt Len Var": safe_stdev(all_lengths) ** 2,
        "FIN Flag Cnt": flags.get('FIN', 0),
        "SYN Flag Cnt": flags.get('SYN', 0),
        "RST Flag Cnt": flags.get('RST', 0),
        "PSH Flag Cnt": flags.get('PSH', 0),
        "ACK Flag Cnt": flags.get('ACK', 0),
        "URG Flag Cnt": flags.get('URG', 0),
        "CWE Flag Count": 0,
        "ECE Flag Cnt": 0,
        "Down/Up Ratio": len(bwd_lengths) / len(fwd_lengths) if len(fwd_lengths) > 0 else 0,
        "Pkt Size Avg": safe_mean(all_lengths),
        "Fwd Seg Size Avg": safe_mean(fwd_lengths),
        "Bwd Seg Size Avg": safe_mean(bwd_lengths),
        "Subflow Fwd Pkts": len(fwd_lengths),
        "Subflow Fwd Byts": sum(fwd_lengths),
        "Subflow Bwd Pkts": len(bwd_lengths),
        "Subflow Bwd Byts": sum(bwd_lengths),
    }


def calculate_iats(times: List[float]) -> List[float]:
    """Tính inter-arrival times."""
    if len(times) < 2:
        return []
    sorted_times = sorted(times)
    return [sorted_times[i] - sorted_times[i-1] for i in range(1, len(sorted_times))]


def safe_mean(values: List) -> float:
    """Tính mean an toàn."""
    return statistics.mean(values) if values else 0


def safe_stdev(values: List) -> float:
    """Tính standard deviation an toàn."""
    return statistics.stdev(values) if len(values) > 1 else 0
