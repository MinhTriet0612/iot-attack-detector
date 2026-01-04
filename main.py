"""
IoT Attack Detection using Graph Neural Networks (GNN) on CICIDS 2018
Complete implementation including data processing, graph construction, and GNN training
"""

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data, DataLoader
from torch_geometric.nn import GCNConv, GATConv, global_mean_pool
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report, confusion_matrix
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict
import warnings
import os
import glob
import pickle
warnings.filterwarnings('ignore')

# ============================================================================
# 1. DATA LOADING AND PREPROCESSING
# ============================================================================

class CICIDS2018DataLoader:
    """Load and preprocess CICIDS 2018 dataset from CSV format"""
    
    def __init__(self, csv_file_path_or_folder):
        self.csv_file_path_or_folder = csv_file_path_or_folder
        self.data = None
        self.feature_columns = None
        self.is_folder = os.path.isdir(csv_file_path_or_folder) if os.path.exists(csv_file_path_or_folder) else False
        
    def load_csv(self):
        """Load CSV file(s) and convert to DataFrame"""
        if self.is_folder:
            return self.load_csv_folder()
        else:
            return self.load_single_csv()
    
    def load_single_csv(self):
        """Load a single CSV file and convert to DataFrame"""
        print(f"Loading CSV file: {self.csv_file_path_or_folder}")
        
        try:
            # Try reading with different encodings
            try:
                self.data = pd.read_csv(self.csv_file_path_or_folder, encoding='utf-8')
            except UnicodeDecodeError:
                self.data = pd.read_csv(self.csv_file_path_or_folder, encoding='latin-1')
            
            print(f"Loaded {len(self.data)} network flows with {len(self.data.columns)} features")
            print(f"Columns: {list(self.data.columns)[:10]}...")  # Show first 10 columns
            
            return self.data
            
        except FileNotFoundError:
            print(f"Error: File '{self.csv_file_path_or_folder}' not found!")
            raise
        except Exception as e:
            print(f"Error loading CSV: {e}")
            raise
    
    def get_csv_files_list(self):
        """Get list of CSV files in folder without loading them"""
        folder_path = self.csv_file_path_or_folder
        if not os.path.isdir(folder_path):
            return []
        
        csv_files = glob.glob(os.path.join(folder_path, "*.csv"))
        csv_files = [f for f in csv_files if not os.path.basename(f).startswith('.~lock')]
        csv_files.sort()
        return csv_files
    
    def load_single_csv_file(self, csv_file_path):
        """Load a single CSV file"""
        try:
            try:
                df = pd.read_csv(csv_file_path, encoding='utf-8', low_memory=False)
            except UnicodeDecodeError:
                df = pd.read_csv(csv_file_path, encoding='latin-1', low_memory=False)
            return df
        except Exception as e:
            print(f"  Error loading {csv_file_path}: {e}")
            return None
    
    def load_csv_folder(self, incremental=False):
        """
        Load CSV files from a folder
        
        Args:
            incremental (bool): If True, returns file list instead of loading all files.
                               If False, loads and combines all files (original behavior).
        """
        folder_path = self.csv_file_path_or_folder
        print(f"Loading CSV files from folder: {folder_path}")
        
        # Find all CSV files in the folder (excluding lock files)
        csv_files = glob.glob(os.path.join(folder_path, "*.csv"))
        # Filter out lock files and other non-data files
        csv_files = [f for f in csv_files if not os.path.basename(f).startswith('.~lock')]
        csv_files.sort()  # Sort for consistent ordering
        
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in folder: {folder_path}")
        
        print(f"Found {len(csv_files)} CSV file(s):")
        for f in csv_files:
            file_size = os.path.getsize(f) / (1024 * 1024)  # Size in MB
            print(f"  - {os.path.basename(f)} ({file_size:.2f} MB)")
        
        if incremental:
            # Return file list for incremental processing
            return csv_files
        
        # Load and combine all CSV files (original behavior)
        dataframes = []
        total_rows = 0
        
        for idx, csv_file in enumerate(csv_files, 1):
            print(f"\n[{idx}/{len(csv_files)}] Loading {os.path.basename(csv_file)}...")
            try:
                # Try reading with different encodings
                try:
                    df = pd.read_csv(csv_file, encoding='utf-8', low_memory=False)
                except UnicodeDecodeError:
                    df = pd.read_csv(csv_file, encoding='latin-1', low_memory=False)
                
                print(f"  Loaded {len(df)} rows, {len(df.columns)} columns")
                dataframes.append(df)
                total_rows += len(df)
                
            except Exception as e:
                print(f"  Warning: Error loading {csv_file}: {e}")
                print(f"  Skipping this file...")
                continue
        
        if not dataframes:
            raise ValueError("No CSV files could be loaded successfully!")
        
        # Combine all dataframes
        print(f"\nCombining {len(dataframes)} dataframes...")
        self.data = pd.concat(dataframes, ignore_index=True)
        
        print(f"\nCombined dataset: {len(self.data)} network flows with {len(self.data.columns)} features")
        print(f"Columns: {list(self.data.columns)[:10]}...")  # Show first 10 columns
        
        return self.data
    
    def preprocess(self):
        """Clean and preprocess the data"""
        print("Preprocessing data...")
        
        # Identify label column (common names in CICIDS dataset)
        label_candidates = ['Label', 'label', 'class', 'Class', 'Attack']
        label_col = None
        for col in label_candidates:
            if col in self.data.columns:
                label_col = col
                break
        
        if label_col is None:
            # If no label found, use last column
            label_col = self.data.columns[-1]
            print(f"Warning: No standard label column found. Using '{label_col}' as label.")
        
        # Rename to 'Label' for consistency
        if label_col != 'Label':
            self.data = self.data.rename(columns={label_col: 'Label'})
        
        print(f"Label column: 'Label'")
        print(f"Unique labels: {self.data['Label'].unique()}")
        
        # Replace 'NaN' and 'Infinity' strings with numeric values
        self.data = self.data.replace(['NaN', 'Infinity', '-Infinity', 'nan', 'inf', '-inf'], 
                                       [np.nan, np.inf, -np.inf, np.nan, np.inf, -np.inf])
        
        # Get feature columns (exclude Label and non-numeric columns)
        exclude_cols = ['Label', 'Timestamp', 'Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Dst Port']
        self.feature_columns = [col for col in self.data.columns 
                                if col not in exclude_cols and col != 'Label']
        
        # Convert numeric columns
        for col in self.feature_columns:
            self.data[col] = pd.to_numeric(self.data[col], errors='coerce')
        
        # Handle missing values and infinities
        self.data[self.feature_columns] = self.data[self.feature_columns].fillna(0)
        self.data[self.feature_columns] = self.data[self.feature_columns].replace([np.inf, -np.inf], 0)
        
        # Remove any remaining non-numeric features
        self.data = self.data[self.feature_columns + ['Label']]
        
        print(f"Preprocessing complete. Features: {len(self.feature_columns)}")
        print(f"Final dataset shape: {self.data.shape}")
        return self.data
    
    def get_statistics(self):
        """Get dataset statistics"""
        stats = {
            'total_samples': len(self.data),
            'benign': len(self.data[self.data['Label'] == 'Benign']),
            'malicious': len(self.data[self.data['Label'] != 'Benign']),
            'features': len(self.feature_columns),
            'label_distribution': self.data['Label'].value_counts().to_dict()
        }
        return stats

# ============================================================================
# 2. GRAPH CONSTRUCTION
# ============================================================================

class NetworkFlowGraphBuilder:
    """Convert network flows to graph structure"""
    
    def __init__(self, data, feature_columns):
        self.data = data
        self.feature_columns = feature_columns
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
    def build_graph(self, fit_scaler=True):
        """
        Build graph from network flows
        Nodes: Unique IP addresses (source and destination)
        Edges: Network flows between IPs
        Node features: Aggregated flow statistics
        Edge features: Flow characteristics
        
        Args:
            fit_scaler (bool): If True, fit the scaler. If False, use existing scaler (transform only).
        """
        print("Building graph structure...")
        
        # Extract features and labels
        X = self.data[self.feature_columns].values
        y = self.data['Label'].values
        
        # Encode labels (0: Benign, 1: Malicious)
        y_binary = np.where(y == 'Benign', 0, 1)
        
        # Normalize features
        if fit_scaler:
            X_normalized = self.scaler.fit_transform(X)
        else:
            X_normalized = self.scaler.transform(X)
        
        # Ensure float32 to avoid dtype mismatch
        X_normalized = X_normalized.astype(np.float32)
        
        # Create simple graph: each flow is a node
        # Edges connect flows with similar characteristics
        num_nodes = len(X_normalized)
        
        # Create edge index based on temporal proximity and feature similarity
        edge_index = self._create_edges(X_normalized, num_nodes)
        
        # Convert to PyTorch tensors with explicit dtype
        x = torch.from_numpy(X_normalized).float()
        y_tensor = torch.from_numpy(y_binary).long()
        edge_index_tensor = torch.from_numpy(edge_index).long()
        
        # Create PyTorch Geometric Data object
        graph_data = Data(x=x, edge_index=edge_index_tensor, y=y_tensor)
        
        print(f"Graph created: {num_nodes} nodes, {edge_index.shape[1]} edges")
        return graph_data, self.scaler, self.label_encoder
    
    def _create_edges(self, X, num_nodes, k_neighbors=5):
        """
        Create edges based on k-nearest neighbors in feature space
        """
        edge_list = []
        
        # For efficiency, limit to subset if dataset is large
        sample_size = min(num_nodes, 1000)
        sample_indices = np.random.choice(num_nodes, sample_size, replace=False)
        X_sample = X[sample_indices]
        
        # Create mapping from sample to original indices
        for idx, i in enumerate(sample_indices):
            # Calculate distances to other sampled nodes
            distances = np.linalg.norm(X_sample - X[i], axis=1)
            # Find k nearest neighbors (excluding self)
            nearest = np.argsort(distances)[1:k_neighbors+1]
            
            # Add edges using original indices
            for neighbor_idx in nearest:
                j = sample_indices[neighbor_idx]
                edge_list.append([i, j])
        
        # Add some random edges to connect the graph better
        num_random_edges = min(sample_size, 500)
        for _ in range(num_random_edges):
            i, j = np.random.choice(sample_indices, 2, replace=False)
            edge_list.append([i, j])
            edge_list.append([j, i])  # Undirected edge
        
        # Convert to numpy array and transpose, ensure int64 for indexing
        if len(edge_list) > 0:
            edge_index = np.array(edge_list, dtype=np.int64).T
        else:
            # Fallback: create simple sequential edges
            edge_index = np.array([[i, i+1] for i in range(num_nodes-1)], dtype=np.int64).T
        
        return edge_index

# ============================================================================
# 3. GNN MODEL ARCHITECTURE
# ============================================================================

class GCN_IoT_Classifier(nn.Module):
    """Graph Convolutional Network for IoT attack detection"""
    
    def __init__(self, num_features, hidden_channels=64, num_classes=2):
        super(GCN_IoT_Classifier, self).__init__()
        
        self.conv1 = GCNConv(num_features, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, hidden_channels)
        self.conv3 = GCNConv(hidden_channels, hidden_channels)
        
        self.lin1 = nn.Linear(hidden_channels, hidden_channels // 2)
        self.lin2 = nn.Linear(hidden_channels // 2, num_classes)
        
        self.dropout = nn.Dropout(0.3)
        
    def forward(self, x, edge_index, batch=None):
        # Graph convolution layers
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)
        
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)
        
        x = self.conv3(x, edge_index)
        x = F.relu(x)
        
        # Fully connected layers
        x = self.lin1(x)
        x = F.relu(x)
        x = self.dropout(x)
        
        x = self.lin2(x)
        
        return F.log_softmax(x, dim=1)

class GAT_IoT_Classifier(nn.Module):
    """Graph Attention Network for IoT attack detection"""
    
    def __init__(self, num_features, hidden_channels=64, num_classes=2, heads=4):
        super(GAT_IoT_Classifier, self).__init__()
        
        self.conv1 = GATConv(num_features, hidden_channels, heads=heads)
        self.conv2 = GATConv(hidden_channels * heads, hidden_channels, heads=heads)
        
        self.lin1 = nn.Linear(hidden_channels * heads, hidden_channels)
        self.lin2 = nn.Linear(hidden_channels, num_classes)
        
        self.dropout = nn.Dropout(0.3)
        
    def forward(self, x, edge_index, batch=None):
        x = self.conv1(x, edge_index)
        x = F.elu(x)
        x = self.dropout(x)
        
        x = self.conv2(x, edge_index)
        x = F.elu(x)
        
        x = self.lin1(x)
        x = F.relu(x)
        x = self.dropout(x)
        
        x = self.lin2(x)
        
        return F.log_softmax(x, dim=1)

# ============================================================================
# 4. TRAINING AND EVALUATION
# ============================================================================

class GNNTrainer:
    """Train and evaluate GNN models"""
    
    def __init__(self, model, data=None, device='cpu'):
        self.device = device
        self.model = model.to(device)
        if data is not None:
            self.data = data.to(device)
        else:
            self.data = None
        self.history = {'train_loss': [], 'train_acc': [], 'val_loss': [], 'val_acc': []}
        self.global_history = {'train_loss': [], 'train_acc': [], 'val_loss': [], 'val_acc': []}
        
        # Print GPU information if using CUDA
        if device.type == 'cuda':
            print(f"\nGPU Information:")
            print(f"  Device: {torch.cuda.get_device_name(device)}")
            print(f"  Memory: {torch.cuda.get_device_properties(device).total_memory / 1024**3:.2f} GB")
            print(f"  CUDA Version: {torch.version.cuda}")
    
    def update_data(self, new_data):
        """Update the graph data (for incremental training)"""
        self.data = new_data.to(self.device)
        # Clear old masks
        if hasattr(self.data, 'train_mask'):
            delattr(self.data, 'train_mask')
        if hasattr(self.data, 'val_mask'):
            delattr(self.data, 'val_mask')
        if hasattr(self.data, 'test_mask'):
            delattr(self.data, 'test_mask')
        
    def split_data(self, train_ratio=0.7, val_ratio=0.15):
        """Split data into train, validation, and test sets with stratified sampling"""
        num_nodes = self.data.num_nodes
        y = self.data.y.cpu().numpy()
        
        # Get indices for each class
        benign_indices = np.where(y == 0)[0]
        malicious_indices = np.where(y == 1)[0]
        
        # Shuffle each class separately
        np.random.seed(42)  # For reproducibility
        np.random.shuffle(benign_indices)
        np.random.shuffle(malicious_indices)
        
        # Calculate split sizes for each class
        benign_train_size = int(train_ratio * len(benign_indices))
        benign_val_size = int(val_ratio * len(benign_indices))
        
        malicious_train_size = int(train_ratio * len(malicious_indices))
        malicious_val_size = int(val_ratio * len(malicious_indices))
        
        # Split each class
        benign_train = benign_indices[:benign_train_size]
        benign_val = benign_indices[benign_train_size:benign_train_size + benign_val_size]
        benign_test = benign_indices[benign_train_size + benign_val_size:]
        
        malicious_train = malicious_indices[:malicious_train_size]
        malicious_val = malicious_indices[malicious_train_size:malicious_train_size + malicious_val_size]
        malicious_test = malicious_indices[malicious_train_size + malicious_val_size:]
        
        # Combine indices
        train_indices = np.concatenate([benign_train, malicious_train])
        val_indices = np.concatenate([benign_val, malicious_val])
        test_indices = np.concatenate([benign_test, malicious_test])
        
        # Shuffle combined indices
        np.random.shuffle(train_indices)
        np.random.shuffle(val_indices)
        np.random.shuffle(test_indices)
        
        # Create masks
        train_mask = torch.zeros(num_nodes, dtype=torch.bool, device=self.device)
        val_mask = torch.zeros(num_nodes, dtype=torch.bool, device=self.device)
        test_mask = torch.zeros(num_nodes, dtype=torch.bool, device=self.device)
        
        # Ensure indices are int64 (long) for indexing
        train_mask[torch.from_numpy(train_indices).long().to(self.device)] = True
        val_mask[torch.from_numpy(val_indices).long().to(self.device)] = True
        test_mask[torch.from_numpy(test_indices).long().to(self.device)] = True
        
        self.data.train_mask = train_mask
        self.data.val_mask = val_mask
        self.data.test_mask = test_mask
        
        # Print class distribution
        train_benign = (self.data.y[train_mask] == 0).sum().item()
        train_malicious = (self.data.y[train_mask] == 1).sum().item()
        val_benign = (self.data.y[val_mask] == 0).sum().item()
        val_malicious = (self.data.y[val_mask] == 1).sum().item()
        test_benign = (self.data.y[test_mask] == 0).sum().item()
        test_malicious = (self.data.y[test_mask] == 1).sum().item()
        
        print(f"Data split: Train={len(train_indices)}, Val={len(val_indices)}, Test={len(test_indices)}")
        print(f"  Train: Benign={train_benign} ({train_benign/len(train_indices)*100:.1f}%), Malicious={train_malicious} ({train_malicious/len(train_indices)*100:.1f}%)")
        print(f"  Val:   Benign={val_benign} ({val_benign/len(val_indices)*100:.1f}%), Malicious={val_malicious} ({val_malicious/len(val_indices)*100:.1f}%)")
        print(f"  Test:  Benign={test_benign} ({test_benign/len(test_indices)*100:.1f}%), Malicious={test_malicious} ({test_malicious/len(test_indices)*100:.1f}%)")
        
    def train_epoch(self, optimizer, class_weights=None, debug=False):
        """Train for one epoch"""
        self.model.train()
        optimizer.zero_grad()
        
        out = self.model(self.data.x, self.data.edge_index)
        y_train = self.data.y[self.data.train_mask]
        
        # Use class weights if provided
        if class_weights is not None:
            loss = F.nll_loss(out[self.data.train_mask], y_train, weight=class_weights)
        else:
            loss = F.nll_loss(out[self.data.train_mask], y_train)
        
        loss.backward()
        optimizer.step()
        
        # Calculate accuracy
        pred = out[self.data.train_mask].argmax(dim=1)
        train_acc = (pred == y_train).sum().item() / self.data.train_mask.sum().item()
        
        # Debug: Check prediction distribution (only if debug=True and first epoch)
        if debug:
            pred_np = pred.cpu().numpy()
            y_train_np = y_train.cpu().numpy()
            benign_pred = (pred_np == 0).sum()
            malicious_pred = (pred_np == 1).sum()
            benign_true = (y_train_np == 0).sum()
            malicious_true = (y_train_np == 1).sum()
            print(f"    Train Predictions: Benign={benign_pred}, Malicious={malicious_pred} | "
                  f"Train True: Benign={benign_true}, Malicious={malicious_true}")
        
        return loss.item(), train_acc
    
    @torch.no_grad()
    def evaluate(self, mask):
        """Evaluate on validation or test set"""
        self.model.eval()
        out = self.model(self.data.x, self.data.edge_index)
        
        loss = F.nll_loss(out[mask], self.data.y[mask])
        pred = out[mask].argmax(dim=1)
        acc = (pred == self.data.y[mask]).sum().item() / mask.sum().item()
        
        return loss.item(), acc, pred
    
    def train(self, epochs=100, lr=0.01, weight_decay=5e-4):
        """Full training loop"""
        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr, weight_decay=weight_decay)
        
        # Calculate class weights to handle imbalanced data
        y_train = self.data.y[self.data.train_mask].cpu().numpy()
        benign_count = (y_train == 0).sum()
        malicious_count = (y_train == 1).sum()
        total = len(y_train)
        
        # Enhanced inverse frequency weighting with stronger emphasis on minority class
        # Use sqrt to reduce extreme weights, but still favor minority class
        if benign_count > 0 and malicious_count > 0:
            ratio = benign_count / malicious_count
            # If benign is much more common, significantly boost malicious weight
            if ratio > 5.0:  # Very imbalanced
                weight_benign = 1.0
                weight_malicious = min(ratio / 2.0, 10.0)  # Cap at 10x
            else:
                weight_benign = total / (2.0 * benign_count)
                weight_malicious = total / (2.0 * malicious_count)
        else:
            weight_benign = 1.0
            weight_malicious = 1.0
        
        class_weights = torch.tensor([weight_benign, weight_malicious], dtype=torch.float32, device=self.device)
        
        print(f"\nClass weights: Benign={weight_benign:.4f}, Malicious={weight_malicious:.4f}")
        print(f"Training set: Benign={benign_count} ({benign_count/total*100:.1f}%), Malicious={malicious_count} ({malicious_count/total*100:.1f}%)")
        print(f"Class ratio (Benign/Malicious): {benign_count/malicious_count if malicious_count > 0 else 'N/A':.2f}")
        
        best_val_acc = 0
        patience = 20
        patience_counter = 0
        
        print("\nTraining started...")
        print("-" * 80)
        
        # Clear GPU cache before training
        if self.device.type == 'cuda':
            torch.cuda.empty_cache()
        
        for epoch in range(epochs):
            # Debug on first epoch
            debug = (epoch == 0)
            train_loss, train_acc = self.train_epoch(optimizer, class_weights=class_weights, debug=debug)
            val_loss, val_acc, val_pred = self.evaluate(self.data.val_mask)
            
            # Debug: Check prediction distribution every 10 epochs
            if (epoch + 1) % 10 == 0:
                val_pred_np = val_pred.cpu().numpy()
                val_y_np = self.data.y[self.data.val_mask].cpu().numpy()
                benign_pred_count = (val_pred_np == 0).sum()
                malicious_pred_count = (val_pred_np == 1).sum()
                benign_true_count = (val_y_np == 0).sum()
                malicious_true_count = (val_y_np == 1).sum()
                
                gpu_info = ""
                if self.device.type == 'cuda':
                    allocated = torch.cuda.memory_allocated(self.device) / 1024**3
                    reserved = torch.cuda.memory_reserved(self.device) / 1024**3
                    gpu_info = f" | GPU Mem: {allocated:.2f}/{reserved:.2f} GB"
                
                print(f"Epoch {epoch+1:03d} | Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.4f} | "
                      f"Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f}{gpu_info}")
                print(f"  Val Predictions: Benign={benign_pred_count}, Malicious={malicious_pred_count} | "
                      f"Val True: Benign={benign_true_count}, Malicious={malicious_true_count}")
            
            self.history['train_loss'].append(train_loss)
            self.history['train_acc'].append(train_acc)
            self.history['val_loss'].append(val_loss)
            self.history['val_acc'].append(val_acc)
            
            # Early stopping
            if val_acc > best_val_acc:
                best_val_acc = val_acc
                patience_counter = 0
                torch.save(self.model.state_dict(), 'best_gnn_model.pt')
            else:
                patience_counter += 1
                
            if patience_counter >= patience:
                print(f"\nEarly stopping at epoch {epoch+1}")
                break
        
        print("-" * 80)
        print(f"Training complete. Best validation accuracy: {best_val_acc:.4f}")
        
        # Load best model
        self.model.load_state_dict(torch.load('best_gnn_model.pt'))
        
        # Clear GPU cache after training
        if self.device.type == 'cuda':
            torch.cuda.empty_cache()
        
        return best_val_acc
    
    def train_incremental(self, epochs_per_file=50, lr=0.01, weight_decay=5e-4, continue_training=True):
        """
        Train incrementally on current data (for use in incremental pipeline)
        
        Args:
            epochs_per_file: Number of epochs to train on each file
            lr: Learning rate
            weight_decay: Weight decay
            continue_training: If True, continue from previous optimizer state
        
        Returns:
            Best validation accuracy for this file
        """
        if continue_training and hasattr(self, 'optimizer'):
            optimizer = self.optimizer
        else:
            optimizer = torch.optim.Adam(self.model.parameters(), lr=lr, weight_decay=weight_decay)
            self.optimizer = optimizer
        
        # Calculate class weights to handle imbalanced data
        y_train = self.data.y[self.data.train_mask].cpu().numpy()
        benign_count = (y_train == 0).sum()
        malicious_count = (y_train == 1).sum()
        total = len(y_train)
        
        # Enhanced inverse frequency weighting with stronger emphasis on minority class
        if benign_count > 0 and malicious_count > 0:
            ratio = benign_count / malicious_count
            # If benign is much more common, significantly boost malicious weight
            if ratio > 5.0:  # Very imbalanced
                weight_benign = 1.0
                weight_malicious = min(ratio / 2.0, 10.0)  # Cap at 10x
            else:
                weight_benign = total / (2.0 * benign_count)
                weight_malicious = total / (2.0 * malicious_count)
        else:
            weight_benign = 1.0
            weight_malicious = 1.0
        
        class_weights = torch.tensor([weight_benign, weight_malicious], dtype=torch.float32, device=self.device)
        
        if not continue_training or not hasattr(self, '_printed_weights'):
            print(f"  Class weights: Benign={weight_benign:.4f}, Malicious={weight_malicious:.4f}")
            print(f"  Training set: Benign={benign_count} ({benign_count/total*100:.1f}%), Malicious={malicious_count} ({malicious_count/total*100:.1f}%)")
            print(f"  Class ratio (Benign/Malicious): {benign_count/malicious_count if malicious_count > 0 else 'N/A':.2f}")
            self._printed_weights = True
        
        best_val_acc = 0
        patience = 10  # Shorter patience for incremental training
        patience_counter = 0
        
        # Clear GPU cache before training
        if self.device.type == 'cuda':
            torch.cuda.empty_cache()
        
        for epoch in range(epochs_per_file):
            # Debug on first epoch of first file
            debug = (epoch == 0 and not continue_training)
            train_loss, train_acc = self.train_epoch(optimizer, class_weights=class_weights, debug=debug)
            val_loss, val_acc, val_pred = self.evaluate(self.data.val_mask)
            
            # Store in local history
            self.history['train_loss'].append(train_loss)
            self.history['train_acc'].append(train_acc)
            self.history['val_loss'].append(val_loss)
            self.history['val_acc'].append(val_acc)
            
            # Store in global history
            self.global_history['train_loss'].append(train_loss)
            self.global_history['train_acc'].append(train_acc)
            self.global_history['val_loss'].append(val_loss)
            self.global_history['val_acc'].append(val_acc)
            
            if (epoch + 1) % 10 == 0:
                # Debug: Check prediction distribution
                val_pred_np = val_pred.cpu().numpy()
                val_y_np = self.data.y[self.data.val_mask].cpu().numpy()
                benign_pred_count = (val_pred_np == 0).sum()
                malicious_pred_count = (val_pred_np == 1).sum()
                benign_true_count = (val_y_np == 0).sum()
                malicious_true_count = (val_y_np == 1).sum()
                
                gpu_info = ""
                if self.device.type == 'cuda':
                    allocated = torch.cuda.memory_allocated(self.device) / 1024**3
                    reserved = torch.cuda.memory_reserved(self.device) / 1024**3
                    gpu_info = f" | GPU Mem: {allocated:.2f}/{reserved:.2f} GB"
                
                print(f"  Epoch {epoch+1:03d}/{epochs_per_file} | Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.4f} | "
                      f"Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f}{gpu_info}")
                print(f"    Val Predictions: Benign={benign_pred_count}, Malicious={malicious_pred_count} | "
                      f"Val True: Benign={benign_true_count}, Malicious={malicious_true_count}")
            
            # Early stopping
            if val_acc > best_val_acc:
                best_val_acc = val_acc
                patience_counter = 0
            else:
                patience_counter += 1
                
            if patience_counter >= patience:
                print(f"  Early stopping at epoch {epoch+1}")
                break
        
        # Clear GPU cache after training
        if self.device.type == 'cuda':
            torch.cuda.empty_cache()
        
        return best_val_acc
        
    def test(self):
        """Evaluate on test set"""
        test_loss, test_acc, pred = self.evaluate(self.data.test_mask)
        
        # Get true labels and predictions
        y_true = self.data.y[self.data.test_mask].cpu().numpy()
        y_pred = pred.cpu().numpy()
        
        # Calculate metrics
        print("\n" + "="*80)
        print("TEST RESULTS")
        print("="*80)
        print(f"Test Accuracy: {test_acc:.4f}")
        print(f"Test Loss: {test_loss:.4f}")
        
        # Calculate per-class metrics
        benign_pred = (y_pred == 0).sum()
        malicious_pred = (y_pred == 1).sum()
        benign_true = (y_true == 0).sum()
        malicious_true = (y_true == 1).sum()
        
        print(f"\nTrue labels:  Benign={benign_true}, Malicious={malicious_true}")
        print(f"Predictions:  Benign={benign_pred}, Malicious={malicious_pred}")
        
        print("\nClassification Report:")
        print(classification_report(y_true, y_pred, target_names=['Benign', 'Malicious']))
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_true, y_pred)
        print(cm)
        print(f"  [Benign predicted as Benign: {cm[0,0]}, as Malicious: {cm[0,1]}]")
        print(f"  [Malicious predicted as Benign: {cm[1,0]}, as Malicious: {cm[1,1]}]")
        
        # Calculate ROC-AUC
        out = self.model(self.data.x, self.data.edge_index)
        y_prob = torch.exp(out[self.data.test_mask])[:, 1].detach().cpu().numpy()
        roc_auc = roc_auc_score(y_true, y_prob)
        print(f"\nROC-AUC Score: {roc_auc:.4f}")
        
        return {
            'accuracy': test_acc,
            'loss': test_loss,
            'roc_auc': roc_auc,
            'confusion_matrix': cm,
            'y_true': y_true,
            'y_pred': y_pred,
            'y_prob': y_prob
        }
    
    def plot_training_history(self):
        """Plot training history"""
        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        
        # Loss plot
        axes[0].plot(self.history['train_loss'], label='Train Loss')
        axes[0].plot(self.history['val_loss'], label='Val Loss')
        axes[0].set_xlabel('Epoch')
        axes[0].set_ylabel('Loss')
        axes[0].set_title('Training and Validation Loss')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)
        
        # Accuracy plot
        axes[1].plot(self.history['train_acc'], label='Train Acc')
        axes[1].plot(self.history['val_acc'], label='Val Acc')
        axes[1].set_xlabel('Epoch')
        axes[1].set_ylabel('Accuracy')
        axes[1].set_title('Training and Validation Accuracy')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('training_history.png', dpi=300, bbox_inches='tight')
        plt.show()

# ============================================================================
# 5. MAIN EXECUTION
# ============================================================================

def train_incremental_pipeline(dataset_folder, force_cpu=False, epochs_per_file=50, 
                                train_ratio=0.7, val_ratio=0.15):
    """
    Incremental training pipeline: Load one file, train, release memory, repeat
    
    Args:
        dataset_folder: Path to folder containing CSV files
        force_cpu: Force CPU usage
        epochs_per_file: Number of epochs to train on each file
        train_ratio: Training set ratio
        val_ratio: Validation set ratio
    """
    print("="*80)
    print("IoT ATTACK DETECTION USING GRAPH NEURAL NETWORKS (INCREMENTAL MODE)")
    print("Dataset: CICIDS 2018")
    print("="*80)
    print("\nMode: Incremental Training (one file at a time)")
    print("This mode loads, trains, and releases memory for each file sequentially.\n")
    
    # Get list of CSV files
    data_loader = CICIDS2018DataLoader(dataset_folder)
    csv_files = data_loader.load_csv_folder(incremental=True)
    
    if not csv_files:
        raise ValueError("No CSV files found!")
    
    # Setup device
    if force_cpu:
        device = torch.device('cpu')
        print(f"⚠ Forcing CPU usage (force_cpu=True)")
    elif torch.cuda.is_available():
        device = torch.device('cuda')
        print(f"✓ CUDA is available!")
        print(f"  GPU: {torch.cuda.get_device_name(0)}")
        gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3
        print(f"  Total GPU Memory: {gpu_memory:.2f} GB")
        torch.cuda.empty_cache()
    else:
        device = torch.device('cpu')
        print(f"⚠ CUDA is not available. Using CPU.")
    
    print(f"\nUsing device: {device}\n")
    
    # Initialize model (will be reused across files)
    model = None
    trainer = None
    feature_columns = None
    scaler = None
    label_encoder = None
    
    all_results = []
    total_samples_processed = 0
    
    # Process each file
    for file_idx, csv_file in enumerate(csv_files, 1):
        print("\n" + "="*80)
        print(f"PROCESSING FILE {file_idx}/{len(csv_files)}: {os.path.basename(csv_file)}")
        print("="*80)
        
        try:
            # 1. Load single CSV file
            print(f"\n[STEP 1] Loading CSV file...")
            df = data_loader.load_single_csv_file(csv_file)
            if df is None:
                print(f"  ⚠ Skipping file due to loading error")
                continue
            
            print(f"  Loaded {len(df)} rows, {len(df.columns)} columns")
            
            # 2. Preprocess
            print(f"\n[STEP 2] Preprocessing...")
            data_loader.data = df
            df = data_loader.preprocess()
            
            # Get feature columns (should be same across files)
            if feature_columns is None:
                feature_columns = data_loader.feature_columns
                print(f"  Feature columns identified: {len(feature_columns)}")
            else:
                # Ensure feature columns match
                if set(feature_columns) != set(data_loader.feature_columns):
                    print(f"  ⚠ Warning: Feature columns differ. Aligning...")
                    common_features = list(set(feature_columns) & set(data_loader.feature_columns))
                    df = df[common_features + ['Label']]
                    feature_columns = common_features
            
            stats = data_loader.get_statistics()
            print(f"  Samples: {stats['total_samples']} | Benign: {stats['benign']} | Malicious: {stats['malicious']}")
            
            # 3. Build graph
            print(f"\n[STEP 3] Building graph structure...")
            graph_builder = NetworkFlowGraphBuilder(df, feature_columns)
            if scaler is None:
                # First file: fit the scaler
                graph_data, scaler, label_encoder = graph_builder.build_graph(fit_scaler=True)
            else:
                # Subsequent files: use existing scaler (transform only)
                graph_builder.scaler = scaler
                graph_data, _, _ = graph_builder.build_graph(fit_scaler=False)
            
            graph_data = graph_data.to(device)
            print(f"  Graph: {graph_data.num_nodes} nodes, {graph_data.num_edges} edges")
            
            # 4. Initialize or update model
            if model is None:
                print(f"\n[STEP 4] Initializing GNN model...")
                model = GCN_IoT_Classifier(
                    num_features=graph_data.num_node_features,
                    hidden_channels=64,
                    num_classes=2
                ).to(device)
                print(f"  Model: {model.__class__.__name__}")
                print(f"  Parameters: {sum(p.numel() for p in model.parameters()):,}")
                
                trainer = GNNTrainer(model, graph_data, device=device)
            else:
                print(f"\n[STEP 4] Updating data for incremental training...")
                trainer.update_data(graph_data)
            
            # 5. Split data
            trainer.split_data(train_ratio=train_ratio, val_ratio=val_ratio)
            
            # 6. Train on this file
            print(f"\n[STEP 5] Training on file {file_idx}/{len(csv_files)}...")
            best_val_acc = trainer.train_incremental(
                epochs_per_file=epochs_per_file,
                lr=0.01,
                weight_decay=5e-4,
                continue_training=(file_idx > 1)  # Continue training from file 2 onwards
            )
            
            # 7. Evaluate
            print(f"\n[STEP 6] Evaluating on test set...")
            test_results = trainer.test()
            
            all_results.append({
                'file': os.path.basename(csv_file),
                'samples': stats['total_samples'],
                'test_accuracy': test_results['accuracy'],
                'test_roc_auc': test_results['roc_auc'],
                'best_val_acc': best_val_acc
            })
            
            total_samples_processed += stats['total_samples']
            
            print(f"\n✓ File {file_idx} complete!")
            print(f"  Test Accuracy: {test_results['accuracy']:.4f}")
            print(f"  Test ROC-AUC: {test_results['roc_auc']:.4f}")
            
            # 8. Release memory
            print(f"\n[STEP 7] Releasing memory...")
            del df, graph_data, graph_builder
            if device.type == 'cuda':
                torch.cuda.empty_cache()
                allocated = torch.cuda.memory_allocated(device) / 1024**3
                print(f"  GPU Memory after cleanup: {allocated:.2f} GB")
            
            # Force garbage collection
            import gc
            gc.collect()
            
        except Exception as e:
            print(f"\n  ✗ Error processing file {csv_file}: {e}")
            print(f"  Continuing with next file...")
            import traceback
            traceback.print_exc()
            continue
    
    # Final summary
    print("\n" + "="*80)
    print("INCREMENTAL TRAINING COMPLETE")
    print("="*80)
    print(f"\nTotal files processed: {len(all_results)}/{len(csv_files)}")
    print(f"Total samples processed: {total_samples_processed:,}")
    
    print(f"\nResults per file:")
    for i, result in enumerate(all_results, 1):
        print(f"  {i}. {result['file']}")
        print(f"     Samples: {result['samples']:,} | Test Acc: {result['test_accuracy']:.4f} | ROC-AUC: {result['test_roc_auc']:.4f}")
    
    if all_results:
        avg_acc = sum(r['test_accuracy'] for r in all_results) / len(all_results)
        avg_auc = sum(r['test_roc_auc'] for r in all_results) / len(all_results)
        print(f"\nAverage Test Accuracy: {avg_acc:.4f}")
        print(f"Average ROC-AUC: {avg_auc:.4f}")
    
    # Save final model and preprocessing artifacts
    torch.save(model.state_dict(), 'best_gnn_model_incremental.pt')
    
    # Save scaler and feature_columns for API use
    import pickle
    with open('scaler_incremental.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    with open('feature_columns_incremental.pkl', 'wb') as f:
        pickle.dump(feature_columns, f)
    
    print(f"\nFinal model saved to: best_gnn_model_incremental.pt")
    print(f"Scaler saved to: scaler_incremental.pkl")
    print(f"Feature columns saved to: feature_columns_incremental.pkl")
    
    # Plot training history from global_history (all files combined)
    if trainer and trainer.global_history and len(trainer.global_history['train_loss']) > 0:
        print(f"\n[STEP 8] Generating training history visualization...")
        # Temporarily swap history to use global_history for plotting
        original_history = trainer.history
        trainer.history = trainer.global_history
        trainer.plot_training_history()
        trainer.history = original_history
        print(f"Training history saved to: training_history.png")
    
    return trainer, all_results


def main(force_cpu=False, incremental=False, epochs_per_file=50):
    """
    Main execution pipeline
    
    Args:
        force_cpu (bool): If True, force CPU usage even if GPU is available.
                         Default: False (uses GPU if available)
        incremental (bool): If True, use incremental training (one file at a time).
                           If False, load all files and combine (original behavior).
                           Default: False
        epochs_per_file (int): Number of epochs per file in incremental mode.
                              Default: 50
    """
    
    print("="*80)
    print("IoT ATTACK DETECTION USING GRAPH NEURAL NETWORKS")
    print("Dataset: CICIDS 2018")
    print("="*80)
    
    # Specify your CSV file path or folder path here
    dataset_folder = 'CIC-IDS-2018-Dataset'  # Folder containing all CSV files
    
    # Use incremental training if requested
    if incremental:
        return train_incremental_pipeline(
            dataset_folder=dataset_folder,
            force_cpu=force_cpu,
            epochs_per_file=epochs_per_file
        )
    
    # Original pipeline (load all files at once)
    print("\nMode: Batch Training (load all files and combine)")
    
    # 1. Load data
    print("\n[STEP 1] Loading and preprocessing data...")
    
    data_loader = CICIDS2018DataLoader(dataset_folder)
    df = data_loader.load_csv()
    df = data_loader.preprocess()
    
    stats = data_loader.get_statistics()
    print(f"\nDataset Statistics:")
    print(f"  Total samples: {stats['total_samples']}")
    print(f"  Benign: {stats['benign']} ({stats['benign']/stats['total_samples']*100:.2f}%)")
    print(f"  Malicious: {stats['malicious']} ({stats['malicious']/stats['total_samples']*100:.2f}%)")
    print(f"  Features: {stats['features']}")
    print(f"\nLabel distribution:")
    for label, count in stats['label_distribution'].items():
        print(f"    {label}: {count}")
    
    # 2. Build graph
    print("\n[STEP 2] Building graph structure...")
    graph_builder = NetworkFlowGraphBuilder(df, data_loader.feature_columns)
    graph_data, scaler, label_encoder = graph_builder.build_graph()
    
    print(f"\nGraph Statistics:")
    print(f"  Nodes: {graph_data.num_nodes}")
    print(f"  Edges: {graph_data.num_edges}")
    print(f"  Node features: {graph_data.num_node_features}")
    
    # 3. Initialize model
    print("\n[STEP 3] Initializing GNN model...")
    
    # GPU setup - check for CUDA availability
    if force_cpu:
        device = torch.device('cpu')
        print(f"⚠ Forcing CPU usage (force_cpu=True)")
    elif torch.cuda.is_available():
        device = torch.device('cuda')
        print(f"✓ CUDA is available!")
        print(f"  GPU: {torch.cuda.get_device_name(0)}")
        print(f"  CUDA Version: {torch.version.cuda}")
        print(f"  PyTorch Version: {torch.__version__}")
        
        # Show GPU memory info
        gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3
        print(f"  Total GPU Memory: {gpu_memory:.2f} GB")
        
        # Clear GPU cache
        torch.cuda.empty_cache()
    else:
        device = torch.device('cpu')
        print(f"⚠ CUDA is not available. Using CPU.")
        print(f"  For GPU training, ensure:")
        print(f"    1. NVIDIA GPU with CUDA support")
        print(f"    2. CUDA toolkit installed")
        print(f"    3. PyTorch with CUDA support installed")
        print(f"    Install with: pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118")
    
    print(f"\nUsing device: {device}")
    
    # Choose model: GCN or GAT
    model = GCN_IoT_Classifier(
        num_features=graph_data.num_node_features,
        hidden_channels=64,
        num_classes=2
    )
    
    print(f"\nModel: {model.__class__.__name__}")
    print(f"Parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Move graph data to device before creating trainer
    print(f"\nMoving graph data to {device}...")
    graph_data = graph_data.to(device)
    
    # 4. Train model
    print("\n[STEP 4] Training model...")
    trainer = GNNTrainer(model, graph_data, device=device)
    trainer.split_data(train_ratio=0.7, val_ratio=0.15)
    trainer.train(epochs=100, lr=0.01, weight_decay=5e-4)
    
    # 5. Evaluate
    print("\n[STEP 5] Evaluating model...")
    results = trainer.test()
    
    # 6. Plot results
    print("\n[STEP 6] Generating visualizations...")
    trainer.plot_training_history()
    
    print("\n" + "="*80)
    print("PIPELINE COMPLETE")
    print("="*80)
    print(f"Final Test Accuracy: {results['accuracy']:.4f}")
    print(f"Final ROC-AUC: {results['roc_auc']:.4f}")
    
    # Save scaler and feature_columns for API use
    import pickle
    with open('scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    with open('feature_columns.pkl', 'wb') as f:
        pickle.dump(data_loader.feature_columns, f)
    
    print(f"\nScaler saved to: scaler.pkl")
    print(f"Feature columns saved to: feature_columns.pkl")
    
    return trainer, results

if __name__ == "__main__":
    # Install required packages:
    # pip install torch torch-geometric scikit-learn pandas numpy matplotlib seaborn
    #
    # For GPU support, install PyTorch with CUDA:
    # pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
    # (Replace cu118 with your CUDA version, e.g., cu121 for CUDA 12.1)
    
    # Usage examples:
    # 1. Default (batch mode - load all files at once):
    #    trainer, results = main()
    #    (Uses GPU if available, otherwise CPU)
    #
    # 2. Incremental mode (load one file, train, release memory, repeat):
    #    trainer, results = main(incremental=True, epochs_per_file=50)
    #    (Better for large datasets that don't fit in memory)
    #
    # 3. Force CPU usage:
    #    trainer, results = main(force_cpu=True)
    #
    # 4. Incremental with custom epochs per file:
    #    trainer, results = main(incremental=True, epochs_per_file=30)
    #
    # 5. Check GPU availability:
    #    import torch
    #    print(f"CUDA available: {torch.cuda.is_available()}")
    #    if torch.cuda.is_available():
    #        print(f"GPU: {torch.cuda.get_device_name(0)}")
    
    # Use incremental mode for memory-efficient training
    trainer, results = main(incremental=True, epochs_per_file=30)
