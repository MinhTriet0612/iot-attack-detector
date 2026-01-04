#!/usr/bin/env python3
"""
Test Script: Simulate Different Attack Scenarios
Tạo các mẫu traffic giả lập từ an toàn đến nguy hiểm để test model.

Usage:
    python test_attack_scenarios.py
"""

import requests
import json

API_URL = "http://localhost:8000"

# =============================================================================
# KỊCH BẢN TEST - Từ An Toàn đến Nguy Hiểm
# =============================================================================

SCENARIOS = {
    # -------------------------------------------------------------------------
    # 1. TRAFFIC AN TOÀN (BENIGN)
    # -------------------------------------------------------------------------
    "1. Normal Web Browsing": {
        "description": "Lướt web bình thường - HTTP request/response cân bằng",
        "features": {
            "Flow Duration": 500000,          # 0.5 giây - thời gian bình thường
            "Total Fwd Packets": 10,          # Gửi 10 gói
            "Total Backward Packets": 12,     # Nhận 12 gói (cân bằng)
            "Total Length of Fwd Packets": 1500,
            "Total Length of Bwd Packets": 45000,  # Nhận nhiều data hơn (tải trang)
            "Flow Bytes/s": 93000,
            "Flow Packets/s": 44,
            "Fwd Packet Length Mean": 150,
            "Bwd Packet Length Mean": 3750,
            "SYN Flag Count": 1,              # 1 SYN bình thường
            "ACK Flag Count": 20,             # Nhiều ACK = kết nối ổn định
            "FIN Flag Count": 2,              # Kết thúc bình thường
            "RST Flag Count": 0,
            "Down/Up Ratio": 1.2,
        },
        "expected": "Benign"
    },
    
    "2. File Download": {
        "description": "Tải file - nhận nhiều data, gửi ít",
        "features": {
            "Flow Duration": 5000000,         # 5 giây
            "Total Fwd Packets": 50,          # Ít gói gửi (ACKs)
            "Total Backward Packets": 500,    # Nhiều gói nhận (data)
            "Total Length of Fwd Packets": 2000,
            "Total Length of Bwd Packets": 750000,
            "Flow Bytes/s": 150400,
            "Flow Packets/s": 110,
            "Fwd Packet Length Mean": 40,     # Gói nhỏ (ACK)
            "Bwd Packet Length Mean": 1500,   # Gói lớn (data)
            "SYN Flag Count": 1,
            "ACK Flag Count": 500,
            "FIN Flag Count": 2,
            "RST Flag Count": 0,
            "Down/Up Ratio": 10,              # Tải nhiều hơn gửi
        },
        "expected": "Benign"
    },
    
    # -------------------------------------------------------------------------
    # 2. TRAFFIC ĐÁNG NGỜ (SUSPICIOUS)
    # -------------------------------------------------------------------------
    "3. Port Scan (Slow)": {
        "description": "Quét port chậm - nhiều kết nối ngắn đến các port khác nhau",
        "features": {
            "Flow Duration": 50000,           # Rất ngắn
            "Total Fwd Packets": 3,           # Ít gói
            "Total Backward Packets": 1,      # Hầu như không phản hồi
            "Total Length of Fwd Packets": 180,
            "Total Length of Bwd Packets": 60,
            "Flow Bytes/s": 4800,
            "Flow Packets/s": 80,
            "Fwd Packet Length Mean": 60,
            "Bwd Packet Length Mean": 60,
            "SYN Flag Count": 2,              # Nhiều SYN
            "ACK Flag Count": 1,
            "FIN Flag Count": 0,
            "RST Flag Count": 1,              # RST = port đóng
            "Down/Up Ratio": 0.33,
        },
        "expected": "Attack (Port Scan)"
    },
    
    "4. Brute Force Login": {
        "description": "Thử đăng nhập nhiều lần - giống nhau, lặp lại",
        "features": {
            "Flow Duration": 100000,
            "Total Fwd Packets": 50,          # Nhiều request giống nhau
            "Total Backward Packets": 50,
            "Total Length of Fwd Packets": 5000,
            "Total Length of Bwd Packets": 5000,
            "Flow Bytes/s": 100000,
            "Flow Packets/s": 1000,
            "Fwd Packet Length Mean": 100,    # Kích thước đều nhau
            "Fwd Packet Length Std": 5,       # Độ lệch thấp = giống nhau
            "Bwd Packet Length Mean": 100,
            "SYN Flag Count": 1,
            "ACK Flag Count": 50,
            "FIN Flag Count": 1,
            "RST Flag Count": 0,
            "Down/Up Ratio": 1.0,
        },
        "expected": "Attack (Brute Force)"
    },
    
    # -------------------------------------------------------------------------
    # 3. TRAFFIC TẤN CÔNG (ATTACK)
    # -------------------------------------------------------------------------
    "5. SYN Flood Attack": {
        "description": "DDoS SYN Flood - gửi hàng ngàn SYN không hoàn tất kết nối",
        "features": {
            "Flow Duration": 1000,            # Rất ngắn
            "Total Fwd Packets": 10000,       # Rất nhiều gói
            "Total Backward Packets": 0,      # Không có phản hồi
            "Total Length of Fwd Packets": 600000,
            "Total Length of Bwd Packets": 0,
            "Flow Bytes/s": 600000000,        # Tốc độ cực cao
            "Flow Packets/s": 10000000,
            "Fwd Packet Length Mean": 60,     # Chỉ header
            "Bwd Packet Length Mean": 0,
            "SYN Flag Count": 10000,          # Toàn SYN
            "ACK Flag Count": 0,              # Không ACK
            "FIN Flag Count": 0,
            "RST Flag Count": 0,
            "Down/Up Ratio": 0,
        },
        "expected": "Attack (DDoS)"
    },
    
    "6. UDP Flood Attack": {
        "description": "DDoS UDP Flood - gửi hàng ngàn gói UDP",
        "features": {
            "Flow Duration": 500,
            "Total Fwd Packets": 50000,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 5000000,
            "Total Length of Bwd Packets": 0,
            "Flow Bytes/s": 10000000000,
            "Flow Packets/s": 100000000,
            "Fwd Packet Length Mean": 100,
            "Bwd Packet Length Mean": 0,
            "SYN Flag Count": 0,              # UDP không có SYN
            "ACK Flag Count": 0,
            "FIN Flag Count": 0,
            "RST Flag Count": 0,
            "Down/Up Ratio": 0,
        },
        "expected": "Attack (DDoS)"
    },
    
    "7. Slowloris Attack": {
        "description": "Slowloris - kết nối chậm, giữ connection mở lâu",
        "features": {
            "Flow Duration": 60000000,        # 60 giây - rất lâu
            "Total Fwd Packets": 10,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 100,
            "Total Length of Bwd Packets": 0,
            "Flow Bytes/s": 1.67,             # Tốc độ cực thấp
            "Flow Packets/s": 0.00017,
            "Fwd Packet Length Mean": 10,     # Gói rất nhỏ
            "Bwd Packet Length Mean": 0,
            "Fwd IAT Mean": 6000000,          # 6 giây giữa mỗi gói
            "SYN Flag Count": 1,
            "ACK Flag Count": 10,
            "FIN Flag Count": 0,
            "RST Flag Count": 0,
            "Down/Up Ratio": 0,
        },
        "expected": "Attack (Slowloris)"
    },
    
    "8. Data Exfiltration": {
        "description": "Đánh cắp dữ liệu - gửi nhiều, nhận ít",
        "features": {
            "Flow Duration": 300000,
            "Total Fwd Packets": 1000,
            "Total Backward Packets": 50,
            "Total Length of Fwd Packets": 5000000,  # Gửi 5MB
            "Total Length of Bwd Packets": 5000,
            "Flow Bytes/s": 16683333,
            "Flow Packets/s": 3500,
            "Fwd Packet Length Mean": 5000,    # Gói lớn
            "Bwd Packet Length Mean": 100,
            "SYN Flag Count": 1,
            "ACK Flag Count": 500,
            "FIN Flag Count": 1,
            "RST Flag Count": 0,
            "Down/Up Ratio": 0.05,             # Ngược với tải file
        },
        "expected": "Attack (Exfiltration)"
    },
}


def test_scenario(name, scenario):
    """Test một kịch bản với API."""
    print(f"\n{'='*60}")
    print(f"📌 {name}")
    print(f"   {scenario['description']}")
    print(f"   Expected: {scenario['expected']}")
    print(f"{'='*60}")
    
    try:
        response = requests.post(
            f"{API_URL}/predict",
            json={"features": scenario['features']},
            timeout=10
        )
        result = response.json()
        
        prediction = result.get('prediction', 'Unknown')
        probability = result.get('probability', 0)
        is_attack = result.get('is_attack', False)
        confidence = result.get('confidence', 'N/A')
        
        # Hiển thị kết quả
        if is_attack:
            print(f"   ⚠️  Result: ATTACK ({prediction})")
        else:
            print(f"   ✅ Result: Benign")
        
        print(f"   📊 Probability: {probability:.4f}")
        print(f"   🎯 Confidence: {confidence}")
        
        # So sánh với expected
        expected_attack = "Attack" in scenario['expected']
        if is_attack == expected_attack:
            print(f"   ✓ Match expected!")
        else:
            print(f"   ✗ MISMATCH - Expected: {scenario['expected']}")
        
        return {
            "name": name,
            "expected": scenario['expected'],
            "predicted": prediction,
            "is_attack": is_attack,
            "probability": probability,
            "match": is_attack == expected_attack
        }
        
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Cannot connect to API. Run: python api.py")
        return None
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return None


def run_all_tests():
    """Chạy tất cả các kịch bản test."""
    print("\n" + "="*60)
    print("🧪 IoT ATTACK DETECTOR - SCENARIO TESTS")
    print("="*60)
    print("\nTesting attack scenarios from SAFE to DANGEROUS...")
    
    # Check API health
    try:
        health = requests.get(f"{API_URL}/health", timeout=5)
        print(f"✓ API is running at {API_URL}")
    except:
        print(f"❌ API not running. Start with: python api.py")
        return
    
    results = []
    for name, scenario in SCENARIOS.items():
        result = test_scenario(name, scenario)
        if result:
            results.append(result)
    
    # Summary
    print("\n" + "="*60)
    print("📊 SUMMARY")
    print("="*60)
    
    matches = sum(1 for r in results if r['match'])
    total = len(results)
    
    print(f"\nTotal scenarios: {total}")
    print(f"Correct predictions: {matches}/{total} ({100*matches/total:.1f}%)")
    
    print("\nDetailed Results:")
    print("-"*60)
    for r in results:
        status = "✓" if r['match'] else "✗"
        print(f"{status} {r['name'][:35]:35} | "
              f"Expected: {r['expected'][:15]:15} | "
              f"Got: {r['predicted'][:15]}")


def test_custom_flow():
    """Cho phép test với features tùy chỉnh."""
    print("\n" + "="*60)
    print("🔧 CUSTOM FLOW TEST")
    print("="*60)
    
    # Ví dụ flow tùy chỉnh
    custom_features = {
        "Flow Duration": 100000,
        "Total Fwd Packets": int(input("Total Fwd Packets: ") or "10"),
        "Total Backward Packets": int(input("Total Backward Packets: ") or "10"),
        "SYN Flag Count": int(input("SYN Flag Count: ") or "1"),
        "ACK Flag Count": int(input("ACK Flag Count: ") or "10"),
    }
    
    response = requests.post(
        f"{API_URL}/predict",
        json={"features": custom_features},
        timeout=10
    )
    result = response.json()
    
    print(f"\n📊 Result: {result['prediction']}")
    print(f"   Is Attack: {result['is_attack']}")
    print(f"   Probability: {result['probability']:.4f}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--custom":
        test_custom_flow()
    else:
        run_all_tests()
