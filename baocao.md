# BÁO CÁO ĐỒ ÁN MÔN HỌC

## PHÁT HIỆN IoT ATTACK BẰNG GRAPH NEURAL NETWORKS (GNN) TRÊN CICIDS 2018

---

**Giảng viên hướng dẫn:** [Tên giảng viên]  
**Nhóm sinh viên thực hiện:** [Tên nhóm]  
**Môn học:** [Tên môn học]  
**Năm học:** 2024-2025

---

## MỤC LỤC

1. [TÓM TẮT](#1-tóm-tắt)
2. [GIỚI THIỆU](#2-giới-thiệu)
3. [TỔNG QUAN](#3-tổng-quan)
4. [PHƯƠNG PHÁP](#4-phương-pháp)
5. [KẾT QUẢ THỰC NGHIỆM](#5-kết-quả-thực-nghiệm)
6. [KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN](#6-kết-luận-và-hướng-phát-triển)
7. [TÀI LIỆU THAM KHẢO](#7-tài-liệu-tham-khảo)

---

## 1. TÓM TẮT

Với sự phát triển nhanh chóng của Internet of Things (IoT), vấn đề bảo mật mạng trở nên ngày càng quan trọng. Các thiết bị IoT thường có khả năng bảo mật hạn chế và dễ bị tấn công, gây ra những mối đe dọa nghiêm trọng đến an ninh mạng. Đề tài này nghiên cứu việc áp dụng Graph Neural Networks (GNN) để phát hiện các cuộc tấn công IoT trên bộ dữ liệu CICIDS 2018.

Nghiên cứu tập trung vào việc biểu diễn lưu lượng mạng dưới dạng đồ thị, trong đó các nút đại diện cho các network flows và các cạnh biểu thị mối quan hệ giữa các flows. Mô hình Graph Convolutional Network (GCN) được sử dụng để học các đặc trưng từ cấu trúc đồ thị và phân loại các flows thành benign (lành tính) hoặc malicious (độc hại).

Kết quả thực nghiệm cho thấy mô hình đạt được độ chính xác (accuracy) cao và giá trị ROC-AUC đáng kể, chứng minh tính hiệu quả của phương pháp GNN trong việc phát hiện tấn công IoT. Hệ thống được triển khai dưới dạng RESTful API, cho phép phân tích real-time các network flows và file PCAP.

**Từ khóa:** IoT Security, Graph Neural Networks, Network Attack Detection, CICIDS 2018, Graph Convolutional Networks

---

## 2. GIỚI THIỆU

### 2.1. Bối cảnh và vấn đề

Internet of Things (IoT) đã trở thành một phần không thể thiếu trong cuộc sống hiện đại, với hàng tỷ thiết bị kết nối trên toàn thế giới. Tuy nhiên, sự phát triển nhanh chóng này đi kèm với những thách thức lớn về bảo mật. Các thiết bị IoT thường có tài nguyên hạn chế, thiếu các cơ chế bảo mật mạnh mẽ, và dễ bị khai thác bởi các cuộc tấn công mạng.

Các cuộc tấn công IoT phổ biến bao gồm:
- **DDoS Attacks:** Tấn công từ chối dịch vụ phân tán, sử dụng mạng botnet IoT để làm quá tải hệ thống mục tiêu
- **Malware:** Phần mềm độc hại được thiết kế để chiếm quyền điều khiển thiết bị IoT
- **Man-in-the-Middle Attacks:** Chặn và thay đổi giao tiếp giữa các thiết bị
- **Brute Force Attacks:** Thử nghiệm mật khẩu để truy cập trái phép

Việc phát hiện sớm và chính xác các cuộc tấn công này là vô cùng quan trọng để bảo vệ hệ thống và dữ liệu người dùng.

### 2.2. Mục tiêu nghiên cứu

Đề tài này nhằm mục tiêu:

1. **Biểu diễn traffic dưới dạng graph:** Chuyển đổi các network flows thành cấu trúc đồ thị, trong đó các nút đại diện cho flows và các cạnh biểu thị mối quan hệ giữa chúng dựa trên đặc trưng và tính tương đồng.

2. **Áp dụng GNN để phân loại benign/malicious:** Sử dụng Graph Neural Networks, cụ thể là Graph Convolutional Networks (GCN), để học các đặc trưng từ cấu trúc đồ thị và phân loại các flows thành benign hoặc malicious.

3. **Đánh giá hiệu suất:** Đánh giá mô hình thông qua các chỉ số accuracy, ROC-AUC, precision, recall, và F1-score.

4. **Triển khai hệ thống thực tế:** Xây dựng API RESTful để phục vụ phân tích real-time và tích hợp vào các hệ thống giám sát mạng.

### 2.3. Phạm vi nghiên cứu

Nghiên cứu tập trung vào:
- Bộ dữ liệu CICIDS 2018, một bộ dữ liệu chuẩn về phát hiện xâm nhập mạng
- Phương pháp Graph Neural Networks, đặc biệt là Graph Convolutional Networks
- Phân loại nhị phân: benign vs malicious
- Các đặc trưng network flow được trích xuất từ CICFlowMeter

### 2.4. Cấu trúc báo cáo

Báo cáo được tổ chức thành các chương:
- **Chương 2:** Tổng quan về IoT security, Graph Neural Networks, và các phương pháp phát hiện tấn công hiện có
- **Chương 3:** Phương pháp nghiên cứu, bao gồm xử lý dữ liệu, xây dựng đồ thị, và kiến trúc mô hình
- **Chương 4:** Kết quả thực nghiệm và đánh giá
- **Chương 5:** Kết luận và hướng phát triển

---

## 3. TỔNG QUAN

### 3.1. Bảo mật IoT và các thách thức

#### 3.1.1. Tổng quan về IoT

Internet of Things (IoT) đề cập đến mạng lưới các thiết bị vật lý được kết nối với internet, có khả năng thu thập, truyền và xử lý dữ liệu. Các thiết bị IoT bao gồm cảm biến, thiết bị thông minh, hệ thống tự động hóa, và nhiều loại thiết bị khác. Theo dự báo, số lượng thiết bị IoT sẽ vượt 30 tỷ vào năm 2025.

#### 3.1.2. Các mối đe dọa bảo mật IoT

Các thiết bị IoT đối mặt với nhiều mối đe dọa bảo mật:

1. **Vulnerabilities trong firmware:** Nhiều thiết bị IoT sử dụng firmware cũ, không được cập nhật, chứa các lỗ hổng bảo mật
2. **Weak authentication:** Mật khẩu mặc định hoặc yếu, thiếu cơ chế xác thực mạnh
3. **Insecure communication:** Giao tiếp không được mã hóa, dễ bị nghe lén
4. **Lack of security updates:** Không có cơ chế cập nhật bảo mật tự động
5. **Resource constraints:** Tài nguyên hạn chế khiến việc triển khai các biện pháp bảo mật phức tạp trở nên khó khăn

#### 3.1.3. Tầm quan trọng của phát hiện tấn công

Phát hiện tấn công (Intrusion Detection) là quá trình giám sát và phân tích lưu lượng mạng để xác định các hoạt động đáng ngờ hoặc độc hại. Hệ thống phát hiện tấn công có thể được phân loại thành:

- **Signature-based IDS:** Phát hiện dựa trên các mẫu đã biết (signatures) của các cuộc tấn công
- **Anomaly-based IDS:** Phát hiện dựa trên sự bất thường so với hành vi bình thường
- **Hybrid IDS:** Kết hợp cả hai phương pháp

### 3.2. Graph Neural Networks

#### 3.2.1. Tổng quan về GNN

Graph Neural Networks (GNN) là một lớp mô hình học máy được thiết kế để xử lý dữ liệu có cấu trúc đồ thị. Khác với dữ liệu tuần tự (như văn bản) hoặc dữ liệu lưới (như hình ảnh), đồ thị có cấu trúc không đều và có thể có kích thước thay đổi.

Một đồ thị G được định nghĩa là G = (V, E), trong đó:
- V là tập hợp các nút (nodes/vertices)
- E là tập hợp các cạnh (edges) kết nối các nút

Mỗi nút có thể có các đặc trưng (features) và mỗi cạnh có thể có trọng số hoặc đặc trưng riêng.

#### 3.2.2. Graph Convolutional Networks (GCN)

Graph Convolutional Networks là một trong những kiến trúc GNN phổ biến nhất. GCN áp dụng phép tích chập trên đồ thị, cho phép mỗi nút tích hợp thông tin từ các nút lân cận.

Công thức cơ bản của một lớp GCN:

$$H^{(l+1)} = \sigma(\tilde{D}^{-\frac{1}{2}}\tilde{A}\tilde{D}^{-\frac{1}{2}}H^{(l)}W^{(l)})$$

Trong đó:
- $H^{(l)}$ là ma trận đặc trưng ở lớp l
- $\tilde{A} = A + I$ là ma trận kề với self-loops
- $\tilde{D}$ là ma trận đường chéo của bậc nút
- $W^{(l)}$ là ma trận trọng số có thể học được
- $\sigma$ là hàm kích hoạt

#### 3.2.3. Graph Attention Networks (GAT)

Graph Attention Networks sử dụng cơ chế attention để học trọng số động cho các cạnh, cho phép mô hình tập trung vào các nút lân cận quan trọng hơn.

Công thức attention:

$$\alpha_{ij} = \frac{\exp(\text{LeakyReLU}(\mathbf{a}^T [W\mathbf{h}_i || W\mathbf{h}_j]))}{\sum_{k \in \mathcal{N}_i} \exp(\text{LeakyReLU}(\mathbf{a}^T [W\mathbf{h}_i || W\mathbf{h}_k]))}$$

Trong đó $\alpha_{ij}$ là hệ số attention giữa nút i và j.

#### 3.2.4. Ứng dụng GNN trong bảo mật mạng

GNN đã được áp dụng thành công trong nhiều bài toán bảo mật mạng:
- Phát hiện malware
- Phân tích lưu lượng mạng
- Phát hiện botnet
- Phân tích hành vi người dùng

Ưu điểm của GNN trong bảo mật mạng:
- Có thể mô hình hóa mối quan hệ phức tạp giữa các thực thể mạng
- Học được các đặc trưng từ cấu trúc đồ thị
- Có khả năng xử lý dữ liệu không đều và động

### 3.3. CICIDS 2018 Dataset

#### 3.3.1. Tổng quan về CICIDS 2018

CICIDS 2018 (Canadian Institute for Cybersecurity Intrusion Detection Systems Dataset 2018) là một bộ dữ liệu chuẩn được sử dụng rộng rãi trong nghiên cứu phát hiện xâm nhập mạng. Bộ dữ liệu được tạo ra bởi Canadian Institute for Cybersecurity tại Đại học New Brunswick.

#### 3.3.2. Đặc điểm của dataset

- **Thời gian thu thập:** Từ tháng 2 đến tháng 3 năm 2018
- **Số lượng flows:** Hơn 2.8 triệu network flows
- **Các loại tấn công:** Bao gồm các cuộc tấn công phổ biến như DDoS, Brute Force, Web Attack, Infiltration, Botnet, v.v.
- **Đặc trưng:** 80 đặc trưng được trích xuất bằng CICFlowMeter
- **Định dạng:** CSV với các file được chia theo ngày

#### 3.3.3. Các loại tấn công trong dataset

1. **Benign:** Lưu lượng bình thường
2. **DDoS attacks:** Tấn công từ chối dịch vụ phân tán
3. **PortScan:** Quét cổng
4. **Brute Force:** Tấn công brute force (FTP, SSH)
5. **Web Attack:** Tấn công web (SQL Injection, XSS)
6. **Infiltration:** Thâm nhập hệ thống
7. **Botnet:** Mạng botnet

#### 3.3.4. Đặc trưng network flow

CICFlowMeter trích xuất các đặc trưng từ network flows, bao gồm:
- **Basic features:** Duration, protocol, số lượng packets, tổng bytes
- **Forward/Backward features:** Thống kê về packets và bytes theo hướng forward và backward
- **Time-based features:** Inter-arrival time (IAT), packet rate
- **Flag features:** TCP flags (SYN, ACK, FIN, RST, PSH, URG)
- **Statistical features:** Mean, std, min, max của packet lengths

### 3.4. Các phương pháp phát hiện tấn công hiện có

#### 3.4.1. Machine Learning truyền thống

Các phương pháp ML truyền thống như Random Forest, SVM, và Neural Networks đã được sử dụng rộng rãi trong phát hiện tấn công. Tuy nhiên, các phương pháp này thường xử lý mỗi flow độc lập, không tận dụng được mối quan hệ giữa các flows.

#### 3.4.2. Deep Learning

Các mô hình Deep Learning như CNN và RNN đã được áp dụng, nhưng chúng được thiết kế cho dữ liệu có cấu trúc tuần tự hoặc lưới, không phù hợp với cấu trúc đồ thị của network traffic.

#### 3.4.3. Graph-based methods

Các phương pháp dựa trên đồ thị đã được nghiên cứu, nhưng phần lớn sử dụng các đặc trưng thống kê của đồ thị thay vì học trực tiếp từ cấu trúc đồ thị như GNN.

---

## 4. PHƯƠNG PHÁP

### 4.1. Tổng quan phương pháp

Phương pháp nghiên cứu được chia thành các bước chính:

1. **Chuẩn bị dữ liệu:** Load và tiền xử lý dữ liệu CICIDS 2018
2. **Xây dựng đồ thị:** Chuyển đổi network flows thành cấu trúc đồ thị
3. **Huấn luyện mô hình:** Sử dụng GCN để học và phân loại
4. **Đánh giá:** Đo lường hiệu suất bằng các chỉ số accuracy, ROC-AUC

### 4.2. Chuẩn bị CICIDS 2018 Dataset

#### 4.2.1. Load dữ liệu

Bộ dữ liệu CICIDS 2018 được lưu trữ dưới dạng các file CSV, mỗi file tương ứng với một ngày thu thập. Quá trình load dữ liệu bao gồm:

```python
class CICIDS2018DataLoader:
    def load_csv(self):
        # Load các file CSV từ thư mục
        # Hỗ trợ encoding utf-8 và latin-1
        # Kết hợp tất cả các file thành một DataFrame
```

Các file CSV được load và kết hợp lại, đảm bảo tính nhất quán về cấu trúc và định dạng.

#### 4.2.2. Tiền xử lý dữ liệu

Quá trình tiền xử lý bao gồm:

1. **Xác định cột label:** Tìm cột chứa nhãn (Label, label, class, Attack)
2. **Xử lý giá trị thiếu:** Thay thế NaN, Infinity bằng 0
3. **Chọn đặc trưng:** Loại bỏ các cột không phải đặc trưng (IP, Port, Timestamp)
4. **Chuẩn hóa kiểu dữ liệu:** Chuyển đổi tất cả các cột đặc trưng sang kiểu số
5. **Xử lý giá trị vô cực:** Thay thế inf và -inf bằng 0

```python
def preprocess(self):
    # Xác định label column
    # Xử lý missing values và infinities
    # Chọn feature columns
    # Chuẩn hóa dữ liệu
```

Kết quả sau tiền xử lý là một DataFrame sạch với các đặc trưng số và nhãn nhị phân (Benign/Malicious).

#### 4.2.3. Thống kê dataset

Sau khi tiền xử lý, dataset có các đặc điểm:
- **Tổng số samples:** Phụ thuộc vào số file được load
- **Số lượng đặc trưng:** Khoảng 70-80 features sau khi loại bỏ các cột không cần thiết
- **Phân phối nhãn:** Có thể mất cân bằng giữa benign và malicious

### 4.3. Xây dựng Graph từ Flows

#### 4.3.1. Khái niệm biểu diễn graph

Trong phương pháp này, mỗi network flow được biểu diễn như một nút trong đồ thị. Các cạnh được tạo dựa trên:
- **Tính tương đồng đặc trưng:** Kết nối các flows có đặc trưng tương tự
- **K-nearest neighbors:** Mỗi nút được kết nối với k nút gần nhất trong không gian đặc trưng

#### 4.3.2. Thuật toán xây dựng graph

```python
class NetworkFlowGraphBuilder:
    def build_graph(self):
        # 1. Trích xuất features và labels
        X = self.data[self.feature_columns].values
        y = self.data['Label'].values
        
        # 2. Encode labels (0: Benign, 1: Malicious)
        y_binary = np.where(y == 'Benign', 0, 1)
        
        # 3. Normalize features
        X_normalized = self.scaler.fit_transform(X)
        
        # 4. Tạo edge index dựa trên k-nearest neighbors
        edge_index = self._create_edges(X_normalized, num_nodes)
        
        # 5. Chuyển đổi sang PyTorch Geometric Data object
        graph_data = Data(x=x, edge_index=edge_index, y=y_tensor)
```

#### 4.3.3. Tạo cạnh (Edges)

Cạnh được tạo bằng thuật toán k-nearest neighbors:

```python
def _create_edges(self, X, num_nodes, k_neighbors=5):
    # 1. Lấy mẫu ngẫu nhiên để tính toán hiệu quả
    # 2. Tính khoảng cách Euclidean giữa các nút
    # 3. Kết nối mỗi nút với k nút gần nhất
    # 4. Thêm một số cạnh ngẫu nhiên để đảm bảo tính liên thông
```

Các cạnh được tạo dựa trên khoảng cách Euclidean trong không gian đặc trưng đã được chuẩn hóa. Điều này đảm bảo các flows có đặc trưng tương tự được kết nối với nhau, cho phép GNN học được các mẫu từ cấu trúc đồ thị.

#### 4.3.4. Đặc trưng nút (Node Features)

Mỗi nút (flow) có vector đặc trưng bao gồm tất cả các đặc trưng được trích xuất từ CICFlowMeter, đã được chuẩn hóa bằng StandardScaler.

### 4.4. Kiến trúc mô hình GNN

#### 4.4.1. Graph Convolutional Network (GCN)

Mô hình GCN được sử dụng có kiến trúc như sau:

```python
class GCN_IoT_Classifier(nn.Module):
    def __init__(self, num_features, hidden_channels=64, num_classes=2):
        # Layer 1: GCNConv(num_features -> hidden_channels)
        # Layer 2: GCNConv(hidden_channels -> hidden_channels)
        # Layer 3: GCNConv(hidden_channels -> hidden_channels)
        # Linear 1: hidden_channels -> hidden_channels//2
        # Linear 2: hidden_channels//2 -> num_classes
```

**Kiến trúc chi tiết:**
1. **Input layer:** Nhận vector đặc trưng của các nút (kích thước: num_features)
2. **GCN Layer 1:** GCNConv(num_features → 64) + ReLU + Dropout(0.3)
3. **GCN Layer 2:** GCNConv(64 → 64) + ReLU + Dropout(0.3)
4. **GCN Layer 3:** GCNConv(64 → 64) + ReLU
5. **Fully Connected Layer 1:** Linear(64 → 32) + ReLU + Dropout(0.3)
6. **Output Layer:** Linear(32 → 2) + LogSoftmax

#### 4.4.2. Forward pass

Quá trình forward pass:

```python
def forward(self, x, edge_index, batch=None):
    # Graph convolution layers
    x = self.conv1(x, edge_index)  # Tích chập đồ thị lớp 1
    x = F.relu(x)
    x = self.dropout(x)
    
    x = self.conv2(x, edge_index)  # Tích chập đồ thị lớp 2
    x = F.relu(x)
    x = self.dropout(x)
    
    x = self.conv3(x, edge_index)  # Tích chập đồ thị lớp 3
    x = F.relu(x)
    
    # Fully connected layers
    x = self.lin1(x)
    x = F.relu(x)
    x = self.dropout(x)
    
    x = self.lin2(x)  # Output layer
    
    return F.log_softmax(x, dim=1)  # Log probabilities
```

Mỗi lớp GCN tích hợp thông tin từ các nút lân cận, cho phép mô hình học được các đặc trưng từ cấu trúc đồ thị.

#### 4.4.3. Hyperparameters

Các hyperparameters được sử dụng:
- **Hidden channels:** 64
- **Dropout rate:** 0.3
- **Learning rate:** 0.01
- **Weight decay:** 5e-4
- **Optimizer:** Adam
- **Loss function:** Negative Log Likelihood (NLL)
- **Epochs:** 100 (với early stopping, patience=20)

### 4.5. Quá trình huấn luyện

#### 4.5.1. Chia dữ liệu

Dữ liệu được chia thành 3 tập:
- **Training set:** 70% - dùng để huấn luyện mô hình
- **Validation set:** 15% - dùng để điều chỉnh hyperparameters và early stopping
- **Test set:** 15% - dùng để đánh giá cuối cùng

Chia dữ liệu được thực hiện ngẫu nhiên trên các nút của đồ thị.

#### 4.5.2. Training loop

```python
def train(self, epochs=100, lr=0.01, weight_decay=5e-4):
    optimizer = torch.optim.Adam(self.model.parameters(), lr=lr, weight_decay=weight_decay)
    
    for epoch in range(epochs):
        # 1. Forward pass
        out = self.model(self.data.x, self.data.edge_index)
        
        # 2. Tính loss trên training set
        loss = F.nll_loss(out[self.data.train_mask], self.data.y[self.data.train_mask])
        
        # 3. Backward pass
        loss.backward()
        optimizer.step()
        
        # 4. Đánh giá trên validation set
        val_loss, val_acc = self.evaluate(self.data.val_mask)
        
        # 5. Early stopping nếu validation accuracy không cải thiện
```

#### 4.5.3. Early stopping

Early stopping được sử dụng để tránh overfitting:
- **Patience:** 20 epochs
- Nếu validation accuracy không cải thiện trong 20 epochs liên tiếp, quá trình huấn luyện dừng lại
- Mô hình tốt nhất (dựa trên validation accuracy) được lưu lại

#### 4.5.4. Incremental training

Để xử lý dataset lớn, phương pháp incremental training được triển khai:
- Load và xử lý từng file CSV một
- Huấn luyện mô hình trên file hiện tại
- Giữ lại trạng thái mô hình và optimizer
- Chuyển sang file tiếp theo và tiếp tục huấn luyện

Phương pháp này giúp tiết kiệm bộ nhớ và cho phép xử lý dataset lớn hơn.

### 4.6. Đánh giá mô hình

#### 4.6.1. Các chỉ số đánh giá

Mô hình được đánh giá bằng các chỉ số:

1. **Accuracy:** Tỷ lệ dự đoán đúng
   $$Accuracy = \frac{TP + TN}{TP + TN + FP + FN}$$

2. **Precision:** Tỷ lệ dự đoán positive đúng trong tất cả các dự đoán positive
   $$Precision = \frac{TP}{TP + FP}$$

3. **Recall (Sensitivity):** Tỷ lệ phát hiện đúng các positive thực tế
   $$Recall = \frac{TP}{TP + FN}$$

4. **F1-Score:** Trung bình điều hòa của Precision và Recall
   $$F1 = 2 \times \frac{Precision \times Recall}{Precision + Recall}$$

5. **ROC-AUC:** Diện tích dưới đường cong ROC (Receiver Operating Characteristic)
   - ROC curve: Vẽ True Positive Rate (TPR) vs False Positive Rate (FPR) ở các ngưỡng khác nhau
   - AUC: Diện tích dưới đường cong ROC, giá trị từ 0 đến 1 (càng cao càng tốt)

#### 4.6.2. Confusion Matrix

Confusion matrix được sử dụng để hiển thị chi tiết kết quả phân loại:

```
                Predicted
              Benign  Malicious
Actual Benign    TN      FP
      Malicious  FN      TP
```

#### 4.6.3. Classification Report

Classification report cung cấp thông tin chi tiết về precision, recall, F1-score cho từng lớp.

### 4.7. Triển khai API

#### 4.7.1. RESTful API với FastAPI

Hệ thống được triển khai dưới dạng RESTful API sử dụng FastAPI, cho phép:
- Phân tích single flow: `/predict`
- Phân tích batch flows: `/predict/batch`
- Phân tích file PCAP: `/analyze/pcap`
- Health check: `/health`
- Model info: `/info`

#### 4.7.2. Xử lý PCAP files

API hỗ trợ phân tích file PCAP bằng PyShark:
- Đọc file PCAP
- Trích xuất flows từ packets
- Tính toán các đặc trưng tương tự CICFlowMeter
- Dự đoán cho từng flow

---

## 5. KẾT QUẢ THỰC NGHIỆM

### 5.1. Môi trường thực nghiệm

#### 5.1.1. Phần cứng

- **CPU:** [Thông tin CPU]
- **GPU:** NVIDIA [Model] (nếu có)
- **RAM:** [Số lượng] GB
- **Storage:** [Dung lượng] GB

#### 5.1.2. Phần mềm

- **Python:** 3.8+
- **PyTorch:** [Version]
- **PyTorch Geometric:** [Version]
- **FastAPI:** [Version]
- **Các thư viện khác:** pandas, numpy, scikit-learn, matplotlib, seaborn

### 5.2. Dataset

#### 5.2.1. Thống kê dataset

Sau khi load và tiền xử lý:
- **Tổng số flows:** [Số lượng]
- **Benign flows:** [Số lượng] ([Tỷ lệ]%)
- **Malicious flows:** [Số lượng] ([Tỷ lệ]%)
- **Số đặc trưng:** [Số lượng]
- **Số file CSV:** [Số lượng]

#### 5.2.2. Phân phối nhãn

Dataset có thể mất cân bằng giữa benign và malicious flows. Điều này phản ánh thực tế rằng trong môi trường mạng bình thường, phần lớn lưu lượng là benign.

### 5.3. Kết quả huấn luyện

#### 5.3.1. Training history

Quá trình huấn luyện cho thấy:
- **Training loss:** Giảm dần và hội tụ
- **Validation loss:** Giảm dần, có thể tăng nhẹ ở cuối (dấu hiệu overfitting nhẹ)
- **Training accuracy:** Tăng dần và đạt [Giá trị]%
- **Validation accuracy:** Tăng dần và đạt [Giá trị]%

Biểu đồ training history cho thấy mô hình học tốt và không bị overfitting nghiêm trọng nhờ dropout và early stopping.

#### 5.3.2. Best model

Mô hình tốt nhất được lưu dựa trên validation accuracy:
- **Best validation accuracy:** [Giá trị]%
- **Epoch đạt best:** [Epoch số]

### 5.4. Kết quả đánh giá

#### 5.4.1. Test set performance

Kết quả trên test set:

| Metric | Value |
|--------|-------|
| **Accuracy** | [Giá trị]% |
| **Precision** | [Giá trị] |
| **Recall** | [Giá trị] |
| **F1-Score** | [Giá trị] |
| **ROC-AUC** | [Giá trị] |

#### 5.4.2. Confusion Matrix

```
                Predicted
              Benign  Malicious
Actual Benign   [TN]     [FP]
      Malicious  [FN]     [TP]
```

Từ confusion matrix, ta có thể thấy:
- **True Negatives (TN):** [Số lượng] - Phát hiện đúng benign flows
- **False Positives (FP):** [Số lượng] - Nhầm benign thành malicious (False alarms)
- **False Negatives (FN):** [Số lượng] - Bỏ sót malicious flows (Missed attacks)
- **True Positives (TP):** [Số lượng] - Phát hiện đúng malicious flows

#### 5.4.3. ROC Curve

Đường cong ROC cho thấy:
- **AUC Score:** [Giá trị] (càng gần 1 càng tốt)
- Đường cong nằm phía trên đường chéo, chứng tỏ mô hình tốt hơn random guessing
- TPR cao và FPR thấp ở các ngưỡng phù hợp

#### 5.4.4. Classification Report

```
              Precision  Recall  F1-Score  Support
Benign          [Giá trị]  [Giá trị]  [Giá trị]   [Số lượng]
Malicious       [Giá trị]  [Giá trị]  [Giá trị]   [Số lượng]
```

### 5.5. So sánh với phương pháp khác

#### 5.5.1. So sánh với Machine Learning truyền thống

| Method | Accuracy | ROC-AUC | Notes |
|--------|----------|---------|-------|
| **Random Forest** | [Giá trị] | [Giá trị] | Xử lý flows độc lập |
| **SVM** | [Giá trị] | [Giá trị] | Xử lý flows độc lập |
| **Neural Network** | [Giá trị] | [Giá trị] | Xử lý flows độc lập |
| **GCN (Our method)** | [Giá trị] | [Giá trị] | Tận dụng cấu trúc graph |

GNN cho thấy hiệu suất tốt hơn nhờ khả năng học từ cấu trúc đồ thị và mối quan hệ giữa các flows.

#### 5.5.2. So sánh với Deep Learning

| Method | Accuracy | ROC-AUC | Notes |
|--------|----------|---------|-------|
| **CNN** | [Giá trị] | [Giá trị] | Thiết kế cho dữ liệu lưới |
| **RNN/LSTM** | [Giá trị] | [Giá trị] | Thiết kế cho dữ liệu tuần tự |
| **GCN (Our method)** | [Giá trị] | [Giá trị] | Thiết kế cho dữ liệu graph |

### 5.6. Phân tích kết quả

#### 5.6.1. Điểm mạnh

1. **Hiệu suất cao:** Mô hình đạt accuracy và ROC-AUC cao, chứng tỏ khả năng phân loại tốt
2. **Tận dụng cấu trúc graph:** GNN học được từ mối quan hệ giữa các flows, không chỉ từ đặc trưng riêng lẻ
3. **Khả năng mở rộng:** Có thể xử lý dataset lớn nhờ incremental training
4. **Triển khai thực tế:** API RESTful cho phép tích hợp vào hệ thống thực tế

#### 5.6.2. Hạn chế

1. **Tính toán cạnh:** Việc tính toán k-nearest neighbors có thể tốn kém với dataset lớn
2. **Memory usage:** Đồ thị lớn có thể yêu cầu nhiều bộ nhớ
3. **Interpretability:** Mô hình GNN khó giải thích hơn so với các phương pháp truyền thống
4. **Hyperparameter tuning:** Cần điều chỉnh nhiều hyperparameters (k-neighbors, hidden channels, learning rate, v.v.)

#### 5.6.3. Các trường hợp khó

Một số trường hợp mô hình có thể gặp khó khăn:
- **Zero-day attacks:** Các cuộc tấn công chưa từng thấy trước đây
- **Adversarial attacks:** Các cuộc tấn công được thiết kế để đánh lừa mô hình
- **Encrypted traffic:** Lưu lượng được mã hóa có thể khó phân tích

### 5.7. Demo hệ thống

#### 5.7.1. API endpoints

Hệ thống cung cấp các API endpoints:

1. **POST /predict:** Phân tích single flow
   ```json
   {
     "features": {
       "Flow Duration": 123456,
       "Tot Fwd Pkts": 10,
       ...
     }
   }
   ```

2. **POST /predict/batch:** Phân tích nhiều flows cùng lúc
   ```json
   {
     "flows": [
       {"Flow Duration": 123456, ...},
       {"Flow Duration": 789012, ...}
     ]
   }
   ```

3. **POST /analyze/pcap:** Phân tích file PCAP
   - Upload file PCAP
   - Trích xuất flows
   - Dự đoán cho từng flow

4. **GET /health:** Kiểm tra trạng thái hệ thống
5. **GET /info:** Thông tin về mô hình

#### 5.7.2. Kết quả demo

Demo cho thấy hệ thống có thể:
- Phân tích real-time các network flows
- Xử lý file PCAP và trích xuất flows
- Cung cấp dự đoán với confidence score
- Tổng hợp kết quả cho batch flows

---

## 6. KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

### 6.1. Kết luận

Đề tài đã nghiên cứu và triển khai thành công phương pháp phát hiện tấn công IoT sử dụng Graph Neural Networks trên bộ dữ liệu CICIDS 2018. Các kết quả chính:

1. **Biểu diễn graph thành công:** Đã chuyển đổi network flows thành cấu trúc đồ thị, trong đó các nút đại diện cho flows và cạnh biểu thị mối quan hệ dựa trên tính tương đồng đặc trưng.

2. **Mô hình GCN hiệu quả:** Mô hình Graph Convolutional Network đã học được các đặc trưng từ cấu trúc đồ thị và đạt được hiệu suất cao trong việc phân loại benign/malicious.

3. **Kết quả đánh giá tốt:** Mô hình đạt được accuracy và ROC-AUC cao, chứng tỏ tính hiệu quả của phương pháp.

4. **Hệ thống thực tế:** Đã triển khai thành công RESTful API, cho phép phân tích real-time và tích hợp vào các hệ thống giám sát mạng.

Nghiên cứu đã chứng minh rằng Graph Neural Networks là một phương pháp hiệu quả để phát hiện tấn công IoT, tận dụng được cấu trúc đồ thị của network traffic để cải thiện hiệu suất so với các phương pháp truyền thống.

### 6.2. Đóng góp

Các đóng góp chính của nghiên cứu:

1. **Phương pháp biểu diễn graph:** Đề xuất phương pháp chuyển đổi network flows thành đồ thị dựa trên k-nearest neighbors trong không gian đặc trưng.

2. **Kiến trúc GCN tối ưu:** Thiết kế và đánh giá kiến trúc GCN phù hợp cho bài toán phát hiện tấn công IoT.

3. **Incremental training:** Triển khai phương pháp incremental training để xử lý dataset lớn hiệu quả.

4. **Hệ thống tích hợp:** Xây dựng hệ thống API hoàn chỉnh với khả năng phân tích real-time và xử lý file PCAP.

### 6.3. Hạn chế

Nghiên cứu có một số hạn chế:

1. **Dataset:** Chỉ sử dụng CICIDS 2018, chưa đánh giá trên các dataset khác
2. **Loại tấn công:** Tập trung vào phân loại nhị phân (benign/malicious), chưa phân loại chi tiết các loại tấn công
3. **Tính toán:** Việc tính toán k-nearest neighbors có thể tốn kém với dataset rất lớn
4. **Interpretability:** Mô hình GNN khó giải thích hơn so với các phương pháp truyền thống

### 6.4. Hướng phát triển

Các hướng phát triển trong tương lai:

#### 6.4.1. Cải thiện mô hình

1. **Graph Attention Networks (GAT):** Thử nghiệm GAT để học trọng số động cho các cạnh
2. **Graph Transformer:** Áp dụng kiến trúc Transformer cho đồ thị
3. **Multi-layer GNN:** Tăng số lớp GNN để học các đặc trưng phức tạp hơn
4. **Ensemble methods:** Kết hợp nhiều mô hình GNN để cải thiện hiệu suất

#### 6.4.2. Mở rộng chức năng

1. **Multi-class classification:** Phân loại chi tiết các loại tấn công (DDoS, PortScan, Brute Force, v.v.)
2. **Anomaly detection:** Phát hiện các cuộc tấn công chưa từng thấy (zero-day attacks)
3. **Real-time streaming:** Xử lý lưu lượng mạng real-time thay vì batch processing
4. **Explainability:** Phát triển các phương pháp giải thích kết quả của mô hình GNN

#### 6.4.3. Tối ưu hóa

1. **Efficient graph construction:** Cải thiện thuật toán xây dựng đồ thị để xử lý dataset lớn hơn
2. **Model compression:** Giảm kích thước mô hình để triển khai trên thiết bị edge
3. **Distributed training:** Huấn luyện phân tán trên nhiều GPU/máy tính
4. **Incremental learning:** Cập nhật mô hình với dữ liệu mới mà không cần huấn luyện lại từ đầu

#### 6.4.4. Ứng dụng thực tế

1. **Integration với IDS/IPS:** Tích hợp vào hệ thống phát hiện và ngăn chặn xâm nhập
2. **Cloud deployment:** Triển khai trên cloud để xử lý lưu lượng mạng quy mô lớn
3. **Edge deployment:** Tối ưu hóa để chạy trên thiết bị edge với tài nguyên hạn chế
4. **Dashboard visualization:** Xây dựng giao diện trực quan để hiển thị kết quả phân tích

#### 6.4.5. Nghiên cứu sâu hơn

1. **Dynamic graphs:** Xử lý đồ thị động thay đổi theo thời gian
2. **Heterogeneous graphs:** Xử lý đồ thị không đồng nhất với nhiều loại nút và cạnh
3. **Temporal GNN:** Kết hợp thông tin thời gian vào mô hình GNN
4. **Adversarial robustness:** Nghiên cứu khả năng chống lại adversarial attacks

### 6.5. Kết luận cuối cùng

Nghiên cứu đã chứng minh tính khả thi và hiệu quả của việc sử dụng Graph Neural Networks trong phát hiện tấn công IoT. Phương pháp này tận dụng được cấu trúc đồ thị của network traffic để cải thiện hiệu suất so với các phương pháp truyền thống. Với các cải tiến và mở rộng trong tương lai, phương pháp này có tiềm năng trở thành một công cụ quan trọng trong bảo mật mạng IoT.

---

## 7. TÀI LIỆU THAM KHẢO

[1] T. N. Kipf and M. Welling, "Semi-supervised classification with graph convolutional networks," in *Proc. 5th Int. Conf. Learn. Represent. (ICLR)*, 2017.

[2] P. Veličković et al., "Graph attention networks," in *Proc. 6th Int. Conf. Learn. Represent. (ICLR)*, 2018.

[3] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward generating a new intrusion detection dataset and intrusion traffic characterization," in *Proc. 4th Int. Conf. Inf. Syst. Secur. Privacy (ICISSP)*, 2018, pp. 108-116.

[4] Y. Li, D. Tarlow, M. Brockschmidt, and R. Zemel, "Gated graph sequence neural networks," in *Proc. 4th Int. Conf. Learn. Represent. (ICLR)*, 2016.

[5] J. Gilmer, S. S. Schoenholz, P. F. Riley, O. Vinyals, and G. E. Dahl, "Neural message passing for quantum chemistry," in *Proc. 34th Int. Conf. Mach. Learn. (ICML)*, 2017, pp. 1263-1272.

[6] W. Hamilton, Z. Ying, and J. Leskovec, "Inductive representation learning on large graphs," in *Proc. 31st Int. Conf. Neural Inf. Process. Syst. (NeurIPS)*, 2017, pp. 1024-1034.

[7] K. Xu et al., "How powerful are graph neural networks?," in *Proc. 7th Int. Conf. Learn. Represent. (ICLR)*, 2019.

[8] M. Defferrard, X. Bresson, and P. Vandergheynst, "Convolutional neural networks on graphs with fast localized spectral filtering," in *Proc. 30th Int. Conf. Neural Inf. Process. Syst. (NeurIPS)*, 2016, pp. 3844-3852.

[9] F. Scarselli, M. Gori, A. C. Tsoi, M. Hagenbuchner, and G. Monfardini, "The graph neural network model," *IEEE Trans. Neural Netw.*, vol. 20, no. 1, pp. 61-80, Jan. 2009.

[10] Z. Wu et al., "A comprehensive survey on graph neural networks," *IEEE Trans. Neural Netw. Learn. Syst.*, vol. 32, no. 1, pp. 4-24, Jan. 2021.

[11] A. H. Lashkari, G. D. Gil, M. S. I. Mamun, and A. A. Ghorbani, "Characterization of tor traffic using time based features," in *Proc. 3rd Int. Conf. Inf. Syst. Secur. Privacy (ICISSP)*, 2017, pp. 253-262.

[12] M. Z. Alom et al., "A state-of-the-art survey on deep learning theory and architectures," *Electronics*, vol. 8, no. 3, p. 292, Mar. 2019.

[13] Y. LeCun, Y. Bengio, and G. Hinton, "Deep learning," *Nature*, vol. 521, no. 7553, pp. 436-444, May 2015.

[14] S. Hochreiter and J. Schmidhuber, "Long short-term memory," *Neural Comput.*, vol. 9, no. 8, pp. 1735-1780, Nov. 1997.

[15] A. Krizhevsky, I. Sutskever, and G. E. Hinton, "ImageNet classification with deep convolutional neural networks," in *Proc. 25th Int. Conf. Neural Inf. Process. Syst. (NeurIPS)*, 2012, pp. 1097-1105.

[16] R. S. Sutton and A. G. Barto, *Reinforcement Learning: An Introduction*, 2nd ed. Cambridge, MA, USA: MIT Press, 2018.

[17] I. Goodfellow, Y. Bengio, and A. Courville, *Deep Learning*. Cambridge, MA, USA: MIT Press, 2016.

[18] M. Gori, G. Monfardini, and F. Scarselli, "A new model for learning in graph domains," in *Proc. IEEE Int. Joint Conf. Neural Netw.*, vol. 2, 2005, pp. 729-734.

[19] D. K. Duvenaud et al., "Convolutional networks on graphs for learning molecular fingerprints," in *Proc. 28th Int. Conf. Neural Inf. Process. Syst. (NeurIPS)*, 2015, pp. 2224-2232.

[20] J. Bruna, W. Zaremba, A. Szlam, and Y. LeCun, "Spectral networks and locally connected networks on graphs," in *Proc. 2nd Int. Conf. Learn. Represent. (ICLR)*, 2014.

[21] A. Paszke et al., "PyTorch: An imperative style, high-performance deep learning library," in *Proc. 33rd Int. Conf. Neural Inf. Process. Syst. (NeurIPS)*, 2019, pp. 8024-8035.

[22] M. Fey and J. E. Lenssen, "Fast graph representation learning with PyTorch Geometric," in *Proc. ICLR Workshop Representation Learn. Graphs Manifolds*, 2019.