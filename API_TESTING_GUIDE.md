# IoT Attack Detection API - Testing Guide

## Overview

This guide provides comprehensive testing examples and information for the IoT Attack Detection API. The API uses a Graph Neural Network (GNN) model to classify network flows as either benign or malicious.

## Quick Start

### 1. Start the API Server

```bash
python api.py
```

The API will be available at: `http://localhost:8000`

### 2. Run Automated Tests

```bash
python test_api.py
```

### 3. View Example Commands

```bash
python test_api.py --examples
```

## API Endpoints

### 1. Health Check
**GET** `/health`

Returns the health status of the API and model.

**Response:**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "device": "cuda",
  "num_features": 75
}
```

**Status Values:**
- `"healthy"`: Model is loaded and ready
- `"degraded"`: Model is not loaded

**cURL Example:**
```bash
curl -X GET "http://localhost:8000/health"
```

**Python Example:**
```python
import requests
response = requests.get("http://localhost:8000/health")
print(response.json())
```

---

### 2. Model Information
**GET** `/info`

Returns detailed information about the loaded model.

**Response:**
```json
{
  "model_type": "GCN_IoT_Classifier",
  "device": "cuda",
  "num_features": 75,
  "num_parameters": 12345,
  "feature_columns": ["Flow Duration", "Total Fwd Packets", ...]
}
```

**cURL Example:**
```bash
curl -X GET "http://localhost:8000/info"
```

**Python Example:**
```python
import requests
response = requests.get("http://localhost:8000/info")
data = response.json()
print(f"Model: {data['model_type']}")
print(f"Features: {data['num_features']}")
print(f"Parameters: {data['num_parameters']:,}")
```

---

### 3. Single Prediction
**POST** `/predict`

Predicts if a single network flow is an attack.

**Request Body:**
```json
{
  "features": {
    "Flow Duration": 123456,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 8,
    "Total Length of Fwd Packets": 1200,
    "Total Length of Bwd Packets": 800,
    ...
  }
}
```

**Response:**
```json
{
  "prediction": "Benign",
  "probability": 0.95,
  "is_attack": false,
  "confidence": "Very High"
}
```

**Confidence Levels:**
- `"Very High"`: Probability ≥ 0.9
- `"High"`: Probability ≥ 0.7
- `"Medium"`: Probability ≥ 0.5
- `"Low"`: Probability < 0.5

**cURL Example:**
```bash
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "features": {
      "Flow Duration": 123456,
      "Total Fwd Packets": 10,
      "Total Backward Packets": 8
    }
  }'
```

**Python Example:**
```python
import requests

flow_data = {
    "features": {
        "Flow Duration": 123456,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 8,
        "Total Length of Fwd Packets": 1200,
        "Total Length of Bwd Packets": 800
    }
}

response = requests.post("http://localhost:8000/predict", json=flow_data)
result = response.json()

print(f"Prediction: {result['prediction']}")
print(f"Probability: {result['probability']:.4f}")
print(f"Is Attack: {result['is_attack']}")
print(f"Confidence: {result['confidence']}")
```

**Note:** Missing features will be automatically filled with 0.

---

### 4. Batch Prediction
**POST** `/predict/batch`

Predicts multiple network flows at once (more efficient for bulk processing).

**Request Body:**
```json
{
  "flows": [
    {"features": {"Flow Duration": 123456, "Total Fwd Packets": 10}},
    {"features": {"Flow Duration": 5000, "Total Fwd Packets": 1000}},
    ...
  ]
}
```

**Response:**
```json
{
  "predictions": [
    {
      "index": 0,
      "prediction": "Benign",
      "probability": 0.95,
      "is_attack": false,
      "confidence": "Very High",
      "attack_probability": 0.05,
      "benign_probability": 0.95
    },
    ...
  ],
  "summary": {
    "total": 10,
    "attacks": 2,
    "benign": 8,
    "attack_rate": 0.2
  }
}
```

**cURL Example:**
```bash
curl -X POST "http://localhost:8000/predict/batch" \
  -H "Content-Type: application/json" \
  -d '{
    "flows": [
      {"features": {"Flow Duration": 123456, "Total Fwd Packets": 10}},
      {"features": {"Flow Duration": 5000, "Total Fwd Packets": 1000}}
    ]
  }'
```

**Python Example:**
```python
import requests

batch_data = {
    "flows": [
        {"features": {"Flow Duration": 123456, "Total Fwd Packets": 10}},
        {"features": {"Flow Duration": 5000, "Total Fwd Packets": 1000}}
    ]
}

response = requests.post("http://localhost:8000/predict/batch", json=batch_data)
result = response.json()

print(f"Total: {result['summary']['total']}")
print(f"Attacks: {result['summary']['attacks']}")
print(f"Benign: {result['summary']['benign']}")
print(f"Attack Rate: {result['summary']['attack_rate']:.2%}")
```

---

## Test Suite

The `test_api.py` file contains comprehensive automated tests:

### Test Categories

1. **Health Check Tests**
   - Basic health endpoint validation
   - Model loading status verification

2. **Info Endpoint Tests**
   - Model information retrieval
   - Feature count validation

3. **Single Prediction Tests**
   - Benign flow prediction
   - Malicious flow prediction
   - Minimal features handling

4. **Batch Prediction Tests**
   - Multiple flow processing
   - Summary statistics validation

5. **Error Handling Tests**
   - Empty features handling
   - Invalid JSON handling

6. **Performance Tests**
   - Single prediction latency
   - Batch prediction throughput

### Running Tests

```bash
# Run all tests
python test_api.py

# View example commands
python test_api.py --examples
```

### Expected Test Results

```
================================================================================
TEST SUMMARY
================================================================================
✓ PASS: Health Check
✓ PASS: Info Endpoint
✓ PASS: Single Prediction (Benign)
✓ PASS: Single Prediction (Malicious)
✓ PASS: Single Prediction (Minimal)
✓ PASS: Batch Prediction
✓ PASS: Error Handling (Empty)
✓ PASS: Error Handling (Invalid JSON)
✓ PASS: Performance (Single)
✓ PASS: Performance (Batch)

Total: 10/10 tests passed (100.0%)
```

---

## Common CICIDS Features

The API expects network flow features from the CICIDS 2018 dataset. Common features include:

### Flow Statistics
- `Flow Duration`: Duration of the flow in microseconds
- `Total Fwd Packets`: Total forward packets
- `Total Backward Packets`: Total backward packets
- `Total Length of Fwd Packets`: Total bytes in forward direction
- `Total Length of Bwd Packets`: Total bytes in backward direction

### Packet Statistics
- `Fwd Packet Length Max/Min/Mean/Std`: Forward packet length statistics
- `Bwd Packet Length Max/Min/Mean/Std`: Backward packet length statistics
- `Packet Length Mean/Std/Variance`: Overall packet statistics

### Timing Statistics
- `Flow IAT Mean/Std`: Inter-arrival time statistics
- `Fwd IAT Total/Mean/Std/Max/Min`: Forward IAT statistics
- `Bwd IAT Total/Mean/Std`: Backward IAT statistics

### Flag Statistics
- `FIN Flag Count`, `SYN Flag Count`, `RST Flag Count`
- `PSH Flag Count`, `ACK Flag Count`, `URG Flag Count`

### Rate Statistics
- `Flow Bytes/s`: Bytes per second
- `Flow Packets/s`: Packets per second
- `Fwd Packets/s`, `Bwd Packets/s`: Directional packet rates

**Note:** If a feature is missing, the API will automatically fill it with 0. However, providing more features will improve prediction accuracy.

---

## Error Codes

| Status Code | Description |
|------------|-------------|
| 200 | Success |
| 400 | Bad Request (invalid input) |
| 500 | Internal Server Error |
| 503 | Service Unavailable (model not loaded) |

---

## Performance Benchmarks

Typical performance on a modern system:

- **Single Prediction**: ~10-50 ms
- **Batch Prediction (50 flows)**: ~100-300 ms
- **Throughput**: ~20-100 predictions/second

Performance depends on:
- Hardware (CPU/GPU)
- Model complexity
- Number of features
- Batch size

---

## Troubleshooting

### Model Not Loaded

**Symptom:** Health check returns `"model_loaded": false`

**Solutions:**
1. Ensure model files exist:
   - `best_gnn_model_incremental.pt` or `best_gnn_model.pt`
   - `scaler_incremental.pkl` or `scaler.pkl`
   - `feature_columns_incremental.pkl` or `feature_columns.pkl`

2. Train the model first:
   ```bash
   python main.py
   ```

3. Check server logs for error messages

### Connection Refused

**Symptom:** Cannot connect to API

**Solutions:**
1. Ensure API server is running: `python api.py`
2. Check if port 8000 is available
3. Verify firewall settings

### Prediction Errors

**Symptom:** 500 error on prediction

**Solutions:**
1. Check that model is loaded (use `/health` endpoint)
2. Verify input JSON format is correct
3. Check server logs for detailed error messages

---

## API Documentation

Interactive API documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## Example Use Cases

### 1. Real-time Network Monitoring

```python
import requests
import time

def monitor_flow(flow_features):
    response = requests.post(
        "http://localhost:8000/predict",
        json={"features": flow_features}
    )
    result = response.json()
    
    if result['is_attack']:
        print(f"⚠ ALERT: Attack detected! Confidence: {result['confidence']}")
    else:
        print(f"✓ Flow is benign (Confidence: {result['confidence']})")
    
    return result

# Monitor flows in real-time
while True:
    flow = get_next_flow()  # Your flow capture function
    monitor_flow(flow)
    time.sleep(1)
```

### 2. Batch Analysis

```python
import requests

def analyze_log_file(log_file):
    flows = parse_log_file(log_file)  # Your parsing function
    
    batch_data = {
        "flows": [{"features": flow} for flow in flows]
    }
    
    response = requests.post(
        "http://localhost:8000/predict/batch",
        json=batch_data
    )
    
    result = response.json()
    
    print(f"Analyzed {result['summary']['total']} flows")
    print(f"Found {result['summary']['attacks']} attacks")
    print(f"Attack rate: {result['summary']['attack_rate']:.2%}")
    
    return result
```

### 3. Integration with SIEM

```python
import requests

def send_to_siem(flow, prediction):
    # Integrate with your SIEM system
    siem_data = {
        "flow": flow,
        "prediction": prediction['prediction'],
        "confidence": prediction['confidence'],
        "timestamp": time.time()
    }
    # Send to SIEM...
    pass

def analyze_and_alert(flow_features):
    response = requests.post(
        "http://localhost:8000/predict",
        json={"features": flow_features}
    )
    result = response.json()
    
    if result['is_attack'] and result['confidence'] in ['High', 'Very High']:
        send_to_siem(flow_features, result)
        trigger_alert(result)
    
    return result
```

---

## Support

For issues or questions:
1. Check server logs
2. Review this documentation
3. Run test suite: `python test_api.py`
4. Check API docs: `http://localhost:8000/docs`

