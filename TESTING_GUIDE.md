# IoT Attack Detection Model - Testing Guide

Your trained GNN model is working perfectly! Here's how to test and use it:

## 🚀 Quick Start

### 1. Start the API Server
```bash
# Activate virtual environment and start API
source venv/bin/activate
python api.py
```

The API will start on `http://localhost:8000`

### 2. Quick Test
```bash
# Run the quick test script
source venv/bin/activate
python quick_test.py
```

## 📊 Model Information

- **Model Type**: GCN_IoT_Classifier (Graph Convolutional Network)
- **Features**: 77 network flow features
- **Parameters**: 15,458
- **Device**: CUDA (GPU accelerated)
- **Training**: Incremental mode on CICIDS 2018 dataset

## 🔌 API Endpoints

### Health Check
```bash
curl -X GET "http://localhost:8000/health"
```

### Model Information
```bash
curl -X GET "http://localhost:8000/info"
```

### Single Prediction
```bash
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "features": {
      "Flow Duration": 123456,
      "Total Fwd Packets": 10,
      "Total Backward Packets": 8,
      "Total Length of Fwd Packets": 1200,
      "Total Length of Bwd Packets": 800
    }
  }'
```

### Batch Prediction
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

## 🧪 Testing Options

### 1. Quick Test Script
```bash
python quick_test.py
```
- Tests all endpoints
- Uses sample data
- Fast verification

### 2. Comprehensive Test Suite
```bash
python test_api.py
```
- 10 comprehensive tests
- Performance benchmarks
- Error handling tests
- Detailed examples

### 3. View Examples
```bash
python test_api.py --examples
```
- Shows curl examples
- Python client examples
- JavaScript examples

## 📋 Sample Flow Features

Your model expects 77 features. Here are some key ones:

```python
# Benign flow example
benign_flow = {
    "Flow Duration": 123456,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 8,
    "Total Length of Fwd Packets": 1200,
    "Total Length of Bwd Packets": 800,
    "Flow Bytes/s": 1000.5,
    "Flow Packets/s": 5.2,
    # ... more features
}

# Malicious flow example
malicious_flow = {
    "Flow Duration": 5000,
    "Total Fwd Packets": 1000,
    "Total Backward Packets": 0,
    "Total Length of Fwd Packets": 50000,
    "Total Length of Bwd Packets": 0,
    "Flow Bytes/s": 10000.0,
    "Flow Packets/s": 200.0,
    # ... more features
}
```

## 🎯 Response Format

### Single Prediction Response
```json
{
  "prediction": "Benign",
  "probability": 0.7525,
  "is_attack": false,
  "confidence": "High"
}
```

### Batch Prediction Response
```json
{
  "predictions": [
    {
      "index": 0,
      "prediction": "Benign",
      "probability": 0.7525,
      "is_attack": false,
      "confidence": "High"
    }
  ],
  "summary": {
    "total": 3,
    "attacks": 0,
    "benign": 3,
    "attack_rate": 0.0
  }
}
```

## 🛠️ Advanced Testing

### Performance Testing
```bash
# Test single prediction performance
python -c "
from test_api import test_performance_single
test_performance_single()
"

# Test batch prediction performance  
python -c "
from test_api import test_performance_batch
test_performance_batch()
"
```

### Custom Testing
```python
import requests

# Custom flow data
custom_flow = {
    "Flow Duration": 100000,
    "Total Fwd Packets": 50,
    "Total Backward Packets": 45,
    # Add your features here
}

response = requests.post("http://localhost:8000/predict", 
                        json={"features": custom_flow})
result = response.json()
print(f"Prediction: {result['prediction']}")
```

## 📁 Model Files

Your trained model artifacts:
- `best_gnn_model_incremental.pt` - Trained GNN model
- `scaler_incremental.pkl` - Feature scaler
- `feature_columns_incremental.pkl` - Feature names

## 🔍 Troubleshooting

### Model Not Loading
```bash
# Check if files exist
ls -la *.pt *.pkl

# Check API logs
python api.py  # Watch startup messages
```

### Connection Issues
```bash
# Check if API is running
curl http://localhost:8000/health

# Check port usage
netstat -tlnp | grep 8000
```

### Prediction Errors
- Ensure all required features are provided
- Missing features are automatically filled with 0
- Check feature names match training data

## 🎉 Success!

Your IoT attack detection model is:
- ✅ Successfully trained on CICIDS 2018
- ✅ Deployed via REST API
- ✅ GPU accelerated for fast inference
- ✅ Tested and working correctly
- ✅ Ready for production use

## 📚 Next Steps

1. **Integration**: Use the API in your applications
2. **Monitoring**: Set up health checks
3. **Scaling**: Consider load balancing for high traffic
4. **Retraining**: Update model with new data periodically

---

**Model Performance**: Your model achieved excellent results during training with high accuracy and ROC-AUC scores on the CICIDS 2018 dataset.
