import torch
import pandas as pd
import numpy as np
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import sys
import pickle
import tempfile
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Add current directory to path to import main
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import GCN_IoT_Classifier, NetworkFlowGraphBuilder, CICIDS2018DataLoader

app = FastAPI(
    title="IoT Attack Detection API",
    description="GNN-based IoT attack detection using Graph Convolutional Networks",
    version="1.0.0"
)

# Configure CORS for all endpoints
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],  # Explicitly allow frontend
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # Explicit methods
    allow_headers=["*"],  # Allows all headers
)

# Global variables to store model and preprocessing state
model = None
scaler = None
feature_columns = None
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model_loaded = False

class FlowData(BaseModel):
    """Input flow data for prediction"""
    features: Dict[str, Any]

class BatchFlowData(BaseModel):
    """Batch input flow data for prediction"""
    flows: List[Dict[str, Any]]

class PredictionResponse(BaseModel):
    """Single prediction response"""
    prediction: str
    probability: float
    is_attack: bool
    confidence: str

class BatchPredictionResponse(BaseModel):
    """Batch prediction response"""
    predictions: List[Dict[str, Any]]
    summary: Dict[str, Any]

class LiveCaptureRequest(BaseModel):
    """Request for live traffic capture"""
    interface: Optional[str] = None  # Network interface. If None, auto-select
    duration: Optional[int] = None  # Capture duration in seconds
    packet_count: Optional[int] = None  # Number of packets to capture
    display_filter: Optional[str] = None  # BPF filter (e.g., "tcp port 80")

def load_model_artifacts(model_type='incremental'):
    """
    Load model, scaler, and feature columns
    
    Args:
        model_type: 'incremental' or 'batch' - which model to load
    """
    global model, scaler, feature_columns, model_loaded
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Determine file names based on model type
    if model_type == 'incremental':
        model_path = os.path.join(base_dir, 'best_gnn_model_incremental.pt')
        scaler_path = os.path.join(base_dir, 'scaler_incremental.pkl')
        features_path = os.path.join(base_dir, 'feature_columns_incremental.pkl')
    else:
        model_path = os.path.join(base_dir, 'best_gnn_model.pt')
        scaler_path = os.path.join(base_dir, 'scaler.pkl')
        features_path = os.path.join(base_dir, 'feature_columns.pkl')
    
    # Try to load artifacts
    if not os.path.exists(model_path):
        # Try alternative model type
        alt_type = 'batch' if model_type == 'incremental' else 'incremental'
        alt_model_path = os.path.join(base_dir, f'best_gnn_model_{alt_type}.pt')
        if os.path.exists(alt_model_path):
            print(f"Model {model_path} not found, trying {alt_model_path}...")
            return load_model_artifacts(alt_type)
        else:
            raise FileNotFoundError(f"Model file not found. Tried: {model_path} and {alt_model_path}")
    
    # Load model
    print(f"Loading model from: {model_path}")
    model_state = torch.load(model_path, map_location=device)
    
    # Load scaler and feature columns
    if os.path.exists(scaler_path) and os.path.exists(features_path):
        print(f"Loading scaler from: {scaler_path}")
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
        
        print(f"Loading feature columns from: {features_path}")
        with open(features_path, 'rb') as f:
            feature_columns = pickle.load(f)
        
        # Initialize model with correct number of features
        num_features = len(feature_columns)
        model = GCN_IoT_Classifier(
            num_features=num_features,
            hidden_channels=64,
            num_classes=2
        )
        model.load_state_dict(model_state)
        model.to(device)
        model.eval()
        model_loaded = True
        
        print(f"✓ Model loaded successfully!")
        print(f"  - Features: {num_features}")
        print(f"  - Device: {device}")
        print(f"  - Model parameters: {sum(p.numel() for p in model.parameters()):,}")
        return True
    else:
        # Fallback: try to infer from sample data
        print(f"⚠ Preprocessing artifacts not found. Attempting to infer from sample data...")
        sample_csv = os.path.join(base_dir, 'data_sample1.csv')
        if os.path.exists(sample_csv):
            try:
                loader = CICIDS2018DataLoader(sample_csv)
                df = loader.load_csv()
                df = loader.preprocess()
                feature_columns = loader.feature_columns
                
                builder = NetworkFlowGraphBuilder(df, feature_columns)
                _, scaler, _ = builder.build_graph()
                
                num_features = len(feature_columns)
                model = GCN_IoT_Classifier(
                    num_features=num_features,
                    hidden_channels=64,
                    num_classes=2
                )
                model.load_state_dict(model_state)
                model.to(device)
                model.eval()
                model_loaded = True
                
                print(f"✓ Model loaded using sample data inference")
                return True
            except Exception as e:
                print(f"✗ Failed to load using sample data: {e}")
                return False
        else:
            print(f"✗ Sample CSV not found at {sample_csv}")
            return False

@app.on_event("startup")
async def startup_event():
    """Load model and preprocessing artifacts on startup"""
    global model_loaded
    
    print("="*60)
    print("Starting IoT Attack Detection API")
    print("="*60)
    
    # Try incremental model first, then batch
    try:
        model_loaded = load_model_artifacts('incremental')
    except Exception as e:
        print(f"Failed to load incremental model: {e}")
        try:
            print("Trying batch model...")
            model_loaded = load_model_artifacts('batch')
        except Exception as e2:
            print(f"Failed to load batch model: {e2}")
            print("⚠ API will not be able to make predictions until model is loaded")
            model_loaded = False
    
    if model_loaded:
        print("="*60)
        print("API ready to accept requests")
        print("="*60)
    else:
        print("="*60)
        print("⚠ WARNING: Model not loaded. Predictions will fail.")
        print("="*60)

def preprocess_flow(flow_features: Dict[str, Any]) -> torch.Tensor:
    """
    Preprocess a single flow for prediction
    
    Args:
        flow_features: Dictionary of feature names to values
        
    Returns:
        Preprocessed tensor ready for model input
    """
    # Convert to DataFrame
    input_df = pd.DataFrame([flow_features])
    
    # Ensure all required features are present
    missing_cols = set(feature_columns) - set(input_df.columns)
    if missing_cols:
        # Fill missing columns with 0
        for col in missing_cols:
            input_df[col] = 0
    
    # Reorder columns to match training
    input_df = input_df[feature_columns]
    
    # Preprocess: Handle numeric and inf
    for col in feature_columns:
        input_df[col] = pd.to_numeric(input_df[col], errors='coerce').fillna(0)
    input_df = input_df.replace([np.inf, -np.inf], 0)
    
    # Normalize
    X_normalized = scaler.transform(input_df.values)
    x_tensor = torch.FloatTensor(X_normalized).to(device)
    
    return x_tensor

def predict_single_flow(x_tensor: torch.Tensor) -> Dict[str, Any]:
    """
    Make prediction for a single flow
    
    Args:
        x_tensor: Preprocessed feature tensor
        
    Returns:
        Dictionary with prediction results
    """
    # Build a minimal graph (single node with self-loop for GNN)
    # For single node, we create a self-connection
    num_nodes = x_tensor.shape[0]
    edge_index = torch.tensor([[i for i in range(num_nodes)], 
                               [i for i in range(num_nodes)]], 
                              dtype=torch.long).to(device)
    
    # Inference
    with torch.no_grad():
        out = model(x_tensor, edge_index)
        prob = torch.exp(out)
        prediction_idx = out.argmax(dim=1).item()
        attack_prob = prob[0, 1].item()
        benign_prob = prob[0, 0].item()
    
    label = "Malicious" if prediction_idx == 1 else "Benign"
    confidence_score = attack_prob if prediction_idx == 1 else benign_prob
    
    # Determine confidence level
    if confidence_score >= 0.9:
        confidence = "Very High"
    elif confidence_score >= 0.7:
        confidence = "High"
    elif confidence_score >= 0.5:
        confidence = "Medium"
    else:
        confidence = "Low"
    
    return {
        "prediction": label,
        "probability": float(confidence_score),
        "is_attack": (prediction_idx == 1),
        "confidence": confidence,
        "attack_probability": float(attack_prob),
        "benign_probability": float(benign_prob)
    }

# {
#     "prediction": "Benign",
#     "probability": 0.7524957060813904,
#     "is_attack": false,
#     "confidence": "High"
# }
@app.post("/predict", response_model=PredictionResponse)
async def predict(flow: FlowData):
    """
    Predict if a single network flow is an attack
    
    Args:
        flow: FlowData containing feature dictionary
        
    Returns:
        PredictionResponse with prediction results
    """
    if not model_loaded or model is None or scaler is None or feature_columns is None:
        raise HTTPException(
            status_code=503, 
            detail="Model or preprocessing components not loaded. Please check server logs."
        )
    
    try:
        # Preprocess flow
        x_tensor = preprocess_flow(flow.features)
        
        # Make prediction
        result = predict_single_flow(x_tensor)
        
        return PredictionResponse(
            prediction=result["prediction"],
            probability=result["probability"],
            is_attack=result["is_attack"],
            confidence=result["confidence"]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

# Response
# {
#     "predictions": [
#         {
#             "index": 0,
#             "prediction": "Benign",
#             "probability": 0.752507209777832,
#             "is_attack": false,
#             "confidence": "High",
#             "attack_probability": 0.24749280512332916,
#             "benign_probability": 0.752507209777832
#         },
#         {
#             "index": 1,
#             "prediction": "Benign",
#             "probability": 0.752507209777832,
#             "is_attack": false,
#             "confidence": "High",
#             "attack_probability": 0.24749280512332916,
#             "benign_probability": 0.752507209777832
#         }
#     ],
#     "summary": {
#         "total": 2,
#         "attacks": 0,
#         "benign": 2,
#         "attack_rate": 0.0
#     }
# }
@app.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(batch: BatchFlowData):
    """
    Predict for multiple network flows at once
    
    Args:
        batch: BatchFlowData containing list of flow feature dictionaries
        
    Returns:
        BatchPredictionResponse with predictions and summary
    """
    if not model_loaded or model is None or scaler is None or feature_columns is None:
        raise HTTPException(
            status_code=503, 
            detail="Model or preprocessing components not loaded. Please check server logs."
        )
    
    try:
        # Preprocess all flows
        flows_df = pd.DataFrame(batch.flows)
        
        # Ensure all required features are present
        missing_cols = set(feature_columns) - set(flows_df.columns)
        if missing_cols:
            for col in missing_cols:
                flows_df[col] = 0
        
        # Reorder columns
        flows_df = flows_df[feature_columns]
        
        # Preprocess
        for col in feature_columns:
            flows_df[col] = pd.to_numeric(flows_df[col], errors='coerce').fillna(0)
        flows_df = flows_df.replace([np.inf, -np.inf], 0)
        
        # Normalize
        X_normalized = scaler.transform(flows_df.values)
        x_tensor = torch.FloatTensor(X_normalized).to(device)
        
        # Build graph for batch (connect all nodes to each other for better GNN performance)
        num_nodes = x_tensor.shape[0]
        if num_nodes > 1:
            # Create edges between all nodes (fully connected)
            edge_list = []
            for i in range(num_nodes):
                for j in range(num_nodes):
                    if i != j:
                        edge_list.append([i, j])
            edge_index = torch.tensor(edge_list, dtype=torch.long).T.to(device)
        else:
            # Single node with self-loop
            edge_index = torch.tensor([[0], [0]], dtype=torch.long).to(device)
        
        # Inference
        with torch.no_grad():
            out = model(x_tensor, edge_index)
            prob = torch.exp(out)
            predictions = out.argmax(dim=1).cpu().numpy()
            attack_probs = prob[:, 1].cpu().numpy()
            benign_probs = prob[:, 0].cpu().numpy()
        
        # Format results
        results = []
        attack_count = 0
        benign_count = 0
        
        for i, (pred_idx, attack_prob, benign_prob) in enumerate(zip(predictions, attack_probs, benign_probs)):
            label = "Malicious" if pred_idx == 1 else "Benign"
            if pred_idx == 1:
                attack_count += 1
            else:
                benign_count += 1
            
            confidence_score = float(attack_prob) if pred_idx == 1 else float(benign_prob)
            if confidence_score >= 0.9:
                confidence = "Very High"
            elif confidence_score >= 0.7:
                confidence = "High"
            elif confidence_score >= 0.5:
                confidence = "Medium"
            else:
                confidence = "Low"
            
            results.append({
                "index": i,
                "prediction": label,
                "probability": float(confidence_score),
                "is_attack": bool(pred_idx == 1),
                "confidence": confidence,
                "attack_probability": float(attack_prob),
                "benign_probability": float(benign_prob)
            })
        
        summary = {
            "total": len(results),
            "attacks": attack_count,
            "benign": benign_count,
            "attack_rate": float(attack_count / len(results)) if len(results) > 0 else 0.0
        }
        
        return BatchPredictionResponse(
            predictions=results,
            summary=summary
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch prediction error: {str(e)}")

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy" if model_loaded else "degraded",
        "model_loaded": model_loaded,
        "device": str(device),
        "num_features": len(feature_columns) if feature_columns else 0
    }

@app.get("/info")
async def info():
    """Get model information"""
    if not model_loaded:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    return {
        "model_type": "GCN_IoT_Classifier",
        "device": str(device),
        "num_features": len(feature_columns) if feature_columns else 0,
        "num_parameters": sum(p.numel() for p in model.parameters()) if model else 0,
        "feature_columns": feature_columns[:10] if feature_columns else []  # Show first 10
    }


@app.post("/analyze/pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    """
    Upload và phân tích file PCAP sử dụng PyShark.
    
    Args:
        file: File PCAP upload
        
    Returns:
        Kết quả phân tích các flows trong file PCAP
    """
    if not model_loaded or model is None or scaler is None or feature_columns is None:
        raise HTTPException(
            status_code=503, 
            detail="Model not loaded. Please check server logs."
        )
    
    # Validate file extension
    if not file.filename.endswith(('.pcap', '.pcapng', '.cap')):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Please upload a PCAP file (.pcap, .pcapng, .cap)"
        )
    
    try:
        # Import pyshark helper
        from pyshark_helper import extract_flows_from_pcap
        
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = tmp_file.name
        
        try:
            # Run PyShark in thread pool to avoid event loop conflict
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                flow_features_list = await loop.run_in_executor(
                    executor, extract_flows_from_pcap, tmp_path
                )
            
            if not flow_features_list:
                return {
                    "filename": file.filename,
                    "status": "no_flows",
                    "message": "No network flows found in the PCAP file",
                    "predictions": [],
                    "summary": {"total": 0, "attacks": 0, "benign": 0, "attack_rate": 0.0}
                }
            
            # Predict each flow
            results = []
            attack_count = 0
            benign_count = 0
            
            for i, flow_features in enumerate(flow_features_list):
                try:
                    x_tensor = preprocess_flow(flow_features)
                    prediction = predict_single_flow(x_tensor)
                    
                    if prediction["is_attack"]:
                        attack_count += 1
                    else:
                        benign_count += 1
                    
                    results.append({
                        "flow_index": i,
                        "prediction": prediction["prediction"],
                        "probability": prediction["probability"],
                        "is_attack": prediction["is_attack"],
                        "confidence": prediction["confidence"]
                    })
                except Exception as e:
                    results.append({
                        "flow_index": i,
                        "error": str(e)
                    })
            
            summary = {
                "total": len(results),
                "attacks": attack_count,
                "benign": benign_count,
                "attack_rate": float(attack_count / len(results)) if results else 0.0
            }
            
            return {
                "filename": file.filename,
                "status": "success",
                "predictions": results,
                "summary": summary
            }
            
        finally:
            # Cleanup temp file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="PyShark not installed. Run: pip install pyshark"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing PCAP: {str(e)}")


@app.get("/interfaces")
async def list_interfaces():
    """
    Liệt kê các network interfaces có sẵn.
    
    Returns:
        Danh sách interfaces và interface được tự động chọn
    """
    try:
        from pyshark_helper import get_available_interfaces, auto_select_interface
        
        interfaces = get_available_interfaces()
        auto_selected = auto_select_interface()
        
        return {
            "interfaces": interfaces,
            "auto_selected": auto_selected,
            "total": len(interfaces)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing interfaces: {str(e)}")


@app.post("/capture/live")
async def capture_live_traffic(request: LiveCaptureRequest):
    """
    Capture live network traffic từ interface và phân tích ngay.
    
    Args:
        request: LiveCaptureRequest chứa:
            - interface: Tên network interface (vd: 'wlp2s0', 'eth0'). Nếu None, tự động chọn
            - duration: Thời gian capture (giây). Phải có duration hoặc packet_count
            - packet_count: Số gói cần capture. Phải có duration hoặc packet_count
            - display_filter: BPF filter tùy chọn (vd: 'tcp port 80')
        
    Returns:
        Kết quả phân tích các flows từ live capture
    """
    if not model_loaded or model is None or scaler is None or feature_columns is None:
        raise HTTPException(
            status_code=503, 
            detail="Model not loaded. Please check server logs."
        )
    
    # Validate request
    if not request.duration and not request.packet_count:
        raise HTTPException(
            status_code=400,
            detail="Must provide either 'duration' (seconds) or 'packet_count'"
        )
    
    if request.duration and request.duration <= 0:
        raise HTTPException(
            status_code=400,
            detail="Duration must be greater than 0"
        )
    
    if request.packet_count and request.packet_count <= 0:
        raise HTTPException(
            status_code=400,
            detail="Packet count must be greater than 0"
        )
    
    try:
        # Import pyshark helper
        from pyshark_helper import capture_live_traffic
        
        # Run capture in thread pool to avoid blocking event loop
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            flow_features_list = await loop.run_in_executor(
                executor,
                capture_live_traffic,
                request.interface,
                request.duration,
                request.packet_count,
                request.display_filter
            )
        
        # Lấy interface thực tế được sử dụng (có thể là auto-selected)
        actual_interface = request.interface
        if actual_interface is None:
            from pyshark_helper import auto_select_interface
            actual_interface = auto_select_interface()
        
        if not flow_features_list:
            return {
                "interface": actual_interface,
                "auto_selected": request.interface is None,
                "status": "no_flows",
                "message": "No network flows found during capture",
                "predictions": [],
                "summary": {"total": 0, "attacks": 0, "benign": 0, "attack_rate": 0.0}
            }
        
        # Predict each flow
        results = []
        attack_count = 0
        benign_count = 0
        
        for i, flow_features in enumerate(flow_features_list):
            try:
                x_tensor = preprocess_flow(flow_features)
                prediction = predict_single_flow(x_tensor)
                
                if prediction["is_attack"]:
                    attack_count += 1
                else:
                    benign_count += 1
                
                results.append({
                    "flow_index": i,
                    "prediction": prediction["prediction"],
                    "probability": prediction["probability"],
                    "is_attack": prediction["is_attack"],
                    "confidence": prediction["confidence"],
                    "attack_probability": prediction.get("attack_probability", 0.0),
                    "benign_probability": prediction.get("benign_probability", 0.0)
                })
            except Exception as e:
                results.append({
                    "flow_index": i,
                    "error": str(e)
                })
        
        summary = {
            "total": len(results),
            "attacks": attack_count,
            "benign": benign_count,
            "attack_rate": float(attack_count / len(results)) if results else 0.0
        }
        
        return {
            "interface": actual_interface,
            "auto_selected": request.interface is None,
            "duration": request.duration,
            "packet_count": request.packet_count,
            "filter": request.display_filter,
            "status": "success",
            "predictions": results,
            "summary": summary
        }
        
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="PyShark not installed. Run: pip install pyshark"
        )
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail="Permission denied. Live capture requires root privileges. Run API with sudo or set capabilities."
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error capturing live traffic: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
