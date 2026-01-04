#!/usr/bin/env python3
"""
Test script for PyShark PCAP endpoint.
Tests the /analyze/pcap endpoint.
"""

import requests
import sys
import os

API_URL = "http://localhost:8000"


def test_pcap_endpoint(pcap_path: str):
    """Test the /analyze/pcap endpoint with a PCAP file."""
    
    print("="*60)
    print("🧪 Testing /analyze/pcap Endpoint")
    print("="*60)
    
    # Check if file exists
    if not os.path.exists(pcap_path):
        print(f"❌ File not found: {pcap_path}")
        return False
    
    # Check API health
    try:
        health = requests.get(f"{API_URL}/health", timeout=5)
        if health.status_code != 200:
            print("❌ API health check failed")
            return False
        print(f"✅ API is running at {API_URL}")
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to API. Run: python api.py")
        return False
    
    # Upload PCAP file
    print(f"\n📂 Uploading: {pcap_path}")
    
    try:
        with open(pcap_path, 'rb') as f:
            files = {'file': (os.path.basename(pcap_path), f, 'application/octet-stream')}
            response = requests.post(
                f"{API_URL}/analyze/pcap",
                files=files,
                timeout=60
            )
        
        if response.status_code != 200:
            print(f"❌ Error {response.status_code}: {response.text}")
            return False
        
        data = response.json()
        
        print(f"\n✅ Analysis Complete!")
        print(f"   Filename: {data.get('filename', 'N/A')}")
        print(f"   Status: {data.get('status', 'N/A')}")
        
        summary = data.get('summary', {})
        print(f"\n📊 Summary:")
        print(f"   Total flows: {summary.get('total', 0)}")
        print(f"   Attacks: {summary.get('attacks', 0)}")
        print(f"   Benign: {summary.get('benign', 0)}")
        print(f"   Attack rate: {summary.get('attack_rate', 0)*100:.1f}%")
        
        predictions = data.get('predictions', [])
        if predictions:
            print(f"\n🔍 Flow Details (first 5):")
            for pred in predictions[:5]:
                if 'error' in pred:
                    print(f"   Flow {pred['flow_index']}: ❌ Error - {pred['error']}")
                else:
                    icon = "⚠️" if pred.get('is_attack') else "✅"
                    print(f"   {icon} Flow {pred['flow_index']}: {pred['prediction']} "
                          f"(Confidence: {pred['confidence']})")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_pcap_endpoint.py <pcap_file>")
        print("\nExample:")
        print("  python test_pcap_endpoint.py /tmp/captured_traffic.pcap")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    success = test_pcap_endpoint(pcap_path)
    sys.exit(0 if success else 1)
