"""
Comprehensive API Testing Guide and Examples
IoT Attack Detection API - Test Suite

This file contains:
1. Health check tests
2. Single prediction tests
3. Batch prediction tests
4. Error handling tests
5. Info endpoint tests
6. Example requests with curl, Python, and JavaScript
"""

import requests
import json
import time
from typing import Dict, Any, List

# API Base URL
BASE_URL = "http://localhost:8000"

# ============================================================================
# 1. HEALTH CHECK TESTS
# ============================================================================

def test_health_check():
    """Test the health check endpoint"""
    print("\n" + "="*80)
    print("TEST 1: Health Check")
    print("="*80)
    
    try:
        response = requests.get(f"{BASE_URL}/health")
        response.raise_for_status()
        data = response.json()
        
        print(f"✓ Status Code: {response.status_code}")
        print(f"✓ Response: {json.dumps(data, indent=2)}")
        
        # Validate response structure
        assert "status" in data
        assert "model_loaded" in data
        assert "device" in data
        assert "num_features" in data
        
        print(f"\n✓ Health Check Status: {data['status']}")
        print(f"✓ Model Loaded: {data['model_loaded']}")
        print(f"✓ Device: {data['device']}")
        print(f"✓ Number of Features: {data['num_features']}")
        
        if not data['model_loaded']:
            print("\n⚠ WARNING: Model is not loaded. Predictions will fail.")
        
        return True
    except requests.exceptions.ConnectionError:
        print("✗ ERROR: Cannot connect to API. Is the server running?")
        print("  Start the server with: python api.py")
        return False
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

# ============================================================================
# 2. INFO ENDPOINT TESTS
# ============================================================================

def test_info_endpoint():
    """Test the info endpoint"""
    print("\n" + "="*80)
    print("TEST 2: Model Information")
    print("="*80)
    
    try:
        response = requests.get(f"{BASE_URL}/info")
        response.raise_for_status()
        data = response.json()
        
        print(f"✓ Status Code: {response.status_code}")
        print(f"✓ Response: {json.dumps(data, indent=2)}")
        
        # Validate response structure
        assert "model_type" in data
        assert "device" in data
        assert "num_features" in data
        assert "num_parameters" in data
        
        print(f"\n✓ Model Type: {data['model_type']}")
        print(f"✓ Device: {data['device']}")
        print(f"✓ Number of Features: {data['num_features']}")
        print(f"✓ Number of Parameters: {data['num_parameters']:,}")
        print(f"✓ Sample Features: {data.get('feature_columns', [])[:5]}")
        
        return True
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 503:
            print("⚠ Model not loaded. Info endpoint unavailable.")
        else:
            print(f"✗ ERROR: {e}")
        return False
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

# ============================================================================
# 3. SAMPLE FLOW DATA (Realistic CICIDS Features)
# ============================================================================

# Example benign flow features (typical network traffic)
BENIGN_FLOW = {
    "Flow Duration": 123456,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 8,
    "Total Length of Fwd Packets": 1200,
    "Total Length of Bwd Packets": 800,
    "Fwd Packet Length Max": 150,
    "Fwd Packet Length Min": 50,
    "Fwd Packet Length Mean": 120,
    "Fwd Packet Length Std": 20,
    "Bwd Packet Length Max": 100,
    "Bwd Packet Length Min": 30,
    "Bwd Packet Length Mean": 80,
    "Bwd Packet Length Std": 15,
    "Flow Bytes/s": 1000.5,
    "Flow Packets/s": 5.2,
    "Flow IAT Mean": 200.3,
    "Flow IAT Std": 50.1,
    "Fwd IAT Total": 2000.0,
    "Fwd IAT Mean": 200.0,
    "Fwd IAT Std": 30.0,
    "Fwd IAT Max": 500.0,
    "Fwd IAT Min": 100.0,
    "Bwd IAT Total": 1500.0,
    "Bwd IAT Mean": 187.5,
    "Bwd IAT Std": 25.0,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": 40,
    "Bwd Header Length": 40,
    "Fwd Packets/s": 2.5,
    "Bwd Packets/s": 2.7,
    "Min Packet Length": 30,
    "Max Packet Length": 150,
    "Packet Length Mean": 100.0,
    "Packet Length Std": 30.0,
    "Packet Length Variance": 900.0,
    "FIN Flag Count": 1,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "ACK Flag Count": 9,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 0.67,
    "Average Packet Size": 100.0,
    "Avg Fwd Segment Size": 120.0,
    "Avg Bwd Segment Size": 100.0,
    "Fwd Header Length.1": 40,
    "Fwd Avg Bytes/Bulk": 0,
    "Fwd Avg Packets/Bulk": 0,
    "Fwd Avg Bulk Rate": 0,
    "Bwd Avg Bytes/Bulk": 0,
    "Bwd Avg Packets/Bulk": 0,
    "Bwd Avg Bulk Rate": 0,
    "Subflow Fwd Packets": 10,
    "Subflow Fwd Bytes": 1200,
    "Subflow Bwd Packets": 8,
    "Subflow Bwd Bytes": 800
}

# Example malicious flow features (suspicious patterns)
MALICIOUS_FLOW = {
    "Flow Duration": 5000,
    "Total Fwd Packets": 1000,
    "Total Backward Packets": 0,
    "Total Length of Fwd Packets": 50000,
    "Total Length of Bwd Packets": 0,
    "Fwd Packet Length Max": 1000,
    "Fwd Packet Length Min": 10,
    "Fwd Packet Length Mean": 50,
    "Fwd Packet Length Std": 100,
    "Bwd Packet Length Max": 0,
    "Bwd Packet Length Min": 0,
    "Bwd Packet Length Mean": 0,
    "Bwd Packet Length Std": 0,
    "Flow Bytes/s": 10000.0,
    "Flow Packets/s": 200.0,
    "Flow IAT Mean": 5.0,
    "Flow IAT Std": 2.0,
    "Fwd IAT Total": 5000.0,
    "Fwd IAT Mean": 5.0,
    "Fwd IAT Std": 2.0,
    "Fwd IAT Max": 10.0,
    "Fwd IAT Min": 1.0,
    "Bwd IAT Total": 0.0,
    "Bwd IAT Mean": 0.0,
    "Bwd IAT Std": 0.0,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": 20,
    "Bwd Header Length": 0,
    "Fwd Packets/s": 200.0,
    "Bwd Packets/s": 0.0,
    "Min Packet Length": 10,
    "Max Packet Length": 1000,
    "Packet Length Mean": 50.0,
    "Packet Length Std": 100.0,
    "Packet Length Variance": 10000.0,
    "FIN Flag Count": 0,
    "SYN Flag Count": 1000,
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "ACK Flag Count": 0,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 0.0,
    "Average Packet Size": 50.0,
    "Avg Fwd Segment Size": 50.0,
    "Avg Bwd Segment Size": 0.0,
    "Fwd Header Length.1": 20,
    "Fwd Avg Bytes/Bulk": 0,
    "Fwd Avg Packets/Bulk": 0,
    "Fwd Avg Bulk Rate": 0,
    "Bwd Avg Bytes/Bulk": 0,
    "Bwd Avg Packets/Bulk": 0,
    "Bwd Avg Bulk Rate": 0,
    "Subflow Fwd Packets": 1000,
    "Subflow Fwd Bytes": 50000,
    "Subflow Bwd Packets": 0,
    "Subflow Bwd Bytes": 0
}

# Minimal flow (only essential features - API will fill missing with 0)
MINIMAL_FLOW = {
    "Flow Duration": 100000,
    "Total Fwd Packets": 5,
    "Total Backward Packets": 5,
    "Total Length of Fwd Packets": 500,
    "Total Length of Bwd Packets": 500
}

# ============================================================================
# 4. SINGLE PREDICTION TESTS
# ============================================================================

def test_single_prediction_benign():
    """Test single prediction with benign flow"""
    print("\n" + "="*80)
    print("TEST 3: Single Prediction - Benign Flow")
    print("="*80)
    
    try:
        payload = {"features": BENIGN_FLOW}
        response = requests.post(f"{BASE_URL}/predict", json=payload)
        response.raise_for_status()
        data = response.json()
        
        print(f"✓ Status Code: {response.status_code}")
        print(f"✓ Response: {json.dumps(data, indent=2)}")
        
        # Validate response structure
        assert "prediction" in data
        assert "probability" in data
        assert "is_attack" in data
        assert "confidence" in data
        
        print(f"\n✓ Prediction: {data['prediction']}")
        print(f"✓ Probability: {data['probability']:.4f}")
        print(f"✓ Is Attack: {data['is_attack']}")
        print(f"✓ Confidence: {data['confidence']}")
        
        return True
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 503:
            print("✗ ERROR: Model not loaded. Cannot make predictions.")
        else:
            print(f"✗ ERROR: {e.response.text}")
        return False
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

def test_single_prediction_malicious():
    """Test single prediction with malicious flow"""
    print("\n" + "="*80)
    print("TEST 4: Single Prediction - Malicious Flow")
    print("="*80)
    
    try:
        payload = {"features": MALICIOUS_FLOW}
        response = requests.post(f"{BASE_URL}/predict", json=payload)
        response.raise_for_status()
        data = response.json()
        
        print(f"✓ Status Code: {response.status_code}")
        print(f"✓ Response: {json.dumps(data, indent=2)}")
        
        print(f"\n✓ Prediction: {data['prediction']}")
        print(f"✓ Probability: {data['probability']:.4f}")
        print(f"✓ Is Attack: {data['is_attack']}")
        print(f"✓ Confidence: {data['confidence']}")
        
        return True
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

def test_single_prediction_minimal():
    """Test single prediction with minimal features"""
    print("\n" + "="*80)
    print("TEST 5: Single Prediction - Minimal Features")
    print("="*80)
    
    try:
        payload = {"features": MINIMAL_FLOW}
        response = requests.post(f"{BASE_URL}/predict", json=payload)
        response.raise_for_status()
        data = response.json()
        
        print(f"✓ Status Code: {response.status_code}")
        print(f"✓ Response: {json.dumps(data, indent=2)}")
        
        print(f"\n✓ Prediction: {data['prediction']}")
        print(f"✓ Probability: {data['probability']:.4f}")
        print(f"✓ Note: Missing features were filled with 0")
        
        return True
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

# ============================================================================
# 5. BATCH PREDICTION TESTS
# ============================================================================

def test_batch_prediction():
    """Test batch prediction with multiple flows"""
    print("\n" + "="*80)
    print("TEST 6: Batch Prediction - Multiple Flows")
    print("="*80)
    
    try:
        payload = {
            "flows": [
                {"features": BENIGN_FLOW},
                {"features": MALICIOUS_FLOW},
                {"features": MINIMAL_FLOW},
                {"features": BENIGN_FLOW}
            ]
        }
        
        response = requests.post(f"{BASE_URL}/predict/batch", json=payload)
        response.raise_for_status()
        data = response.json()
        
        print(f"✓ Status Code: {response.status_code}")
        print(f"✓ Response Summary: {json.dumps(data['summary'], indent=2)}")
        print(f"\n✓ Total Flows: {data['summary']['total']}")
        print(f"✓ Attacks Detected: {data['summary']['attacks']}")
        print(f"✓ Benign Flows: {data['summary']['benign']}")
        print(f"✓ Attack Rate: {data['summary']['attack_rate']:.2%}")
        
        print(f"\n✓ Individual Predictions:")
        for i, pred in enumerate(data['predictions'][:3], 1):  # Show first 3
            print(f"  Flow {i}: {pred['prediction']} (Confidence: {pred['confidence']}, Prob: {pred['probability']:.4f})")
        
        return True
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

# ============================================================================
# 6. ERROR HANDLING TESTS
# ============================================================================

def test_error_handling_empty_features():
    """Test error handling with empty features"""
    print("\n" + "="*80)
    print("TEST 7: Error Handling - Empty Features")
    print("="*80)
    
    try:
        payload = {"features": {}}
        response = requests.post(f"{BASE_URL}/predict", json=payload)
        
        if response.status_code == 200:
            print("✓ API handled empty features gracefully (filled with 0)")
            data = response.json()
            print(f"  Prediction: {data['prediction']}")
        else:
            print(f"⚠ Status Code: {response.status_code}")
            print(f"  Response: {response.text}")
        
        return True
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

def test_error_handling_invalid_json():
    """Test error handling with invalid JSON"""
    print("\n" + "="*80)
    print("TEST 8: Error Handling - Invalid JSON")
    print("="*80)
    
    try:
        response = requests.post(
            f"{BASE_URL}/predict",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        
        print(f"✓ Status Code: {response.status_code}")
        if response.status_code != 200:
            print(f"✓ API correctly rejected invalid JSON")
        
        return True
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

# ============================================================================
# 7. PERFORMANCE TESTS
# ============================================================================

def test_performance_single():
    """Test single prediction performance"""
    print("\n" + "="*80)
    print("TEST 9: Performance - Single Prediction")
    print("="*80)
    
    try:
        payload = {"features": BENIGN_FLOW}
        
        times = []
        for i in range(10):
            start = time.time()
            response = requests.post(f"{BASE_URL}/predict", json=payload)
            end = time.time()
            times.append((end - start) * 1000)  # Convert to ms
            response.raise_for_status()
        
        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)
        
        print(f"✓ Completed 10 predictions")
        print(f"✓ Average Time: {avg_time:.2f} ms")
        print(f"✓ Min Time: {min_time:.2f} ms")
        print(f"✓ Max Time: {max_time:.2f} ms")
        
        return True
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

def test_performance_batch():
    """Test batch prediction performance"""
    print("\n" + "="*80)
    print("TEST 10: Performance - Batch Prediction")
    print("="*80)
    
    try:
        # Create batch of 50 flows
        flows = [{"features": BENIGN_FLOW} for _ in range(50)]
        payload = {"flows": flows}
        
        start = time.time()
        response = requests.post(f"{BASE_URL}/predict/batch", json=payload)
        end = time.time()
        response.raise_for_status()
        
        elapsed = (end - start) * 1000  # Convert to ms
        data = response.json()
        
        print(f"✓ Processed {data['summary']['total']} flows")
        print(f"✓ Total Time: {elapsed:.2f} ms")
        print(f"✓ Time per Flow: {elapsed / data['summary']['total']:.2f} ms")
        
        return True
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

# ============================================================================
# 8. RUN ALL TESTS
# ============================================================================

def run_all_tests():
    """Run all tests"""
    print("\n" + "="*80)
    print("IoT ATTACK DETECTION API - COMPREHENSIVE TEST SUITE")
    print("="*80)
    print(f"\nTesting API at: {BASE_URL}")
    print(f"Make sure the API server is running: python api.py")
    print("\nPress Enter to start tests...")
    input()
    
    results = []
    
    # Health and Info Tests
    results.append(("Health Check", test_health_check()))
    results.append(("Info Endpoint", test_info_endpoint()))
    
    # Single Prediction Tests
    results.append(("Single Prediction (Benign)", test_single_prediction_benign()))
    results.append(("Single Prediction (Malicious)", test_single_prediction_malicious()))
    results.append(("Single Prediction (Minimal)", test_single_prediction_minimal()))
    
    # Batch Prediction Tests
    results.append(("Batch Prediction", test_batch_prediction()))
    
    # Error Handling Tests
    results.append(("Error Handling (Empty)", test_error_handling_empty_features()))
    results.append(("Error Handling (Invalid JSON)", test_error_handling_invalid_json()))
    
    # Performance Tests
    results.append(("Performance (Single)", test_performance_single()))
    results.append(("Performance (Batch)", test_performance_batch()))
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    return passed == total

# ============================================================================
# 9. CURL EXAMPLES
# ============================================================================

CURL_EXAMPLES = """
# ============================================================================
# CURL COMMAND EXAMPLES
# ============================================================================

# 1. Health Check
curl -X GET "http://localhost:8000/health"

# 2. Model Information
curl -X GET "http://localhost:8000/info"

# 3. Single Prediction (Benign Flow)
curl -X POST "http://localhost:8000/predict" \\
  -H "Content-Type: application/json" \\
  -d '{
    "features": {
      "Flow Duration": 123456,
      "Total Fwd Packets": 10,
      "Total Backward Packets": 8,
      "Total Length of Fwd Packets": 1200,
      "Total Length of Bwd Packets": 800
    }
  }'

# 4. Single Prediction (Malicious Flow)
curl -X POST "http://localhost:8000/predict" \\
  -H "Content-Type: application/json" \\
  -d '{
    "features": {
      "Flow Duration": 5000,
      "Total Fwd Packets": 1000,
      "Total Backward Packets": 0,
      "Total Length of Fwd Packets": 50000,
      "Total Length of Bwd Packets": 0
    }
  }'

# 5. Batch Prediction
curl -X POST "http://localhost:8000/predict/batch" \\
  -H "Content-Type: application/json" \\
  -d '{
    "flows": [
      {"features": {"Flow Duration": 123456, "Total Fwd Packets": 10}},
      {"features": {"Flow Duration": 5000, "Total Fwd Packets": 1000}}
    ]
  }'

# 6. Pretty Print JSON Response
curl -X GET "http://localhost:8000/health" | python -m json.tool

"""

# ============================================================================
# 10. PYTHON EXAMPLES
# ============================================================================

PYTHON_EXAMPLES = """
# ============================================================================
# PYTHON CLIENT EXAMPLES
# ============================================================================

import requests
import json

BASE_URL = "http://localhost:8000"

# 1. Health Check
response = requests.get(f"{BASE_URL}/health")
print(json.dumps(response.json(), indent=2))

# 2. Model Information
response = requests.get(f"{BASE_URL}/info")
print(json.dumps(response.json(), indent=2))

# 3. Single Prediction
flow_data = {
    "features": {
        "Flow Duration": 123456,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 8,
        "Total Length of Fwd Packets": 1200,
        "Total Length of Bwd Packets": 800
    }
}

response = requests.post(f"{BASE_URL}/predict", json=flow_data)
result = response.json()
print(f"Prediction: {result['prediction']}")
print(f"Probability: {result['probability']:.4f}")
print(f"Is Attack: {result['is_attack']}")
print(f"Confidence: {result['confidence']}")

# 4. Batch Prediction
batch_data = {
    "flows": [
        {"features": {"Flow Duration": 123456, "Total Fwd Packets": 10}},
        {"features": {"Flow Duration": 5000, "Total Fwd Packets": 1000}}
    ]
}

response = requests.post(f"{BASE_URL}/predict/batch", json=batch_data)
result = response.json()
print(f"Total: {result['summary']['total']}")
print(f"Attacks: {result['summary']['attacks']}")
print(f"Benign: {result['summary']['benign']}")

"""

# ============================================================================
# 11. JAVASCRIPT EXAMPLES
# ============================================================================

JAVASCRIPT_EXAMPLES = """
// ============================================================================
// JAVASCRIPT CLIENT EXAMPLES
// ============================================================================

const BASE_URL = "http://localhost:8000";

// 1. Health Check
async function checkHealth() {
  const response = await fetch(`${BASE_URL}/health`);
  const data = await response.json();
  console.log(data);
}

// 2. Single Prediction
async function predictFlow(flowFeatures) {
  const response = await fetch(`${BASE_URL}/predict`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      features: flowFeatures
    })
  });
  
  const result = await response.json();
  console.log(`Prediction: ${result.prediction}`);
  console.log(`Probability: ${result.probability}`);
  console.log(`Is Attack: ${result.is_attack}`);
  console.log(`Confidence: ${result.confidence}`);
  
  return result;
}

// Example usage
const flowData = {
  "Flow Duration": 123456,
  "Total Fwd Packets": 10,
  "Total Backward Packets": 8,
  "Total Length of Fwd Packets": 1200,
  "Total Length of Bwd Packets": 800
};

predictFlow(flowData);

// 3. Batch Prediction
async function predictBatch(flows) {
  const response = await fetch(`${BASE_URL}/predict/batch`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      flows: flows
    })
  });
  
  const result = await response.json();
  console.log(`Total: ${result.summary.total}`);
  console.log(`Attacks: ${result.summary.attacks}`);
  console.log(`Benign: ${result.summary.benign}`);
  
  return result;
}

"""

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--examples":
        # Print examples
        print(CURL_EXAMPLES)
        print("\n" + "="*80 + "\n")
        print(PYTHON_EXAMPLES)
        print("\n" + "="*80 + "\n")
        print(JAVASCRIPT_EXAMPLES)
    else:
        # Run tests
        success = run_all_tests()
        sys.exit(0 if success else 1)
