# 🦈 Wireshark Integration Guide

Hướng dẫn đơn giản nhất để phân tích network traffic với IoT Attack Detector.

---

## 🚀 Quick Start (2 bước đơn giản - KHÔNG CẦN TSHARK!)

### Bước 1: Chạy API
```bash
# Chạy với sudo để có quyền capture (hoặc set capabilities)
sudo python api.py
```

### Bước 2: Capture và phân tích trực tiếp
```bash
# Tự động chọn interface và capture 60 giây
curl -X POST "http://localhost:8000/capture/live" \
  -H "Content-Type: application/json" \
  -d '{"duration": 60}'
```

**Xong!** 🎉 Không cần tshark command line, không cần chỉ định interface!

---

## 📋 Chi tiết từng bước

### 1️⃣ Xem danh sách interfaces (Tùy chọn)

```bash
# Xem interfaces có sẵn và interface được tự động chọn
curl "http://localhost:8000/interfaces"
```

Hoặc dùng lệnh:
```bash
ip link show
```

Output ví dụ:
- `wlp2s0` ← Wi-Fi (thường được tự động chọn)
- `eth0` hoặc `enp3s0` ← Ethernet
- `lo` ← Loopback (tự động bỏ qua)

### 2️⃣ Capture và phân tích live traffic (MỚI! ✅)

**Cách 1: Tự động chọn interface (Đơn giản nhất! ⭐)**
```bash
# Không cần chỉ định interface - tự động chọn!
curl -X POST "http://localhost:8000/capture/live" \
  -H "Content-Type: application/json" \
  -d '{"duration": 60}'
```

**Cách 2: Chỉ định interface thủ công**
```bash
curl -X POST "http://localhost:8000/capture/live" \
  -H "Content-Type: application/json" \
  -d '{"interface": "wlp2s0", "duration": 60}'
```

**Cách 3: Capture số gói cụ thể (tự động chọn interface)**
```bash
curl -X POST "http://localhost:8000/capture/live" \
  -H "Content-Type: application/json" \
  -d '{"packet_count": 100}'
```

**Cách 4: Capture với filter (chỉ HTTP/HTTPS)**
```bash
curl -X POST "http://localhost:8000/capture/live" \
  -H "Content-Type: application/json" \
  -d '{"duration": 60, "display_filter": "tcp port 80 or tcp port 443"}'
```

### 3️⃣ Phân tích file PCAP (nếu đã có file)

**Cách 1: Upload file PCAP qua API**
```bash
curl -X POST "http://localhost:8000/analyze/pcap" \
  -F "file=@/tmp/traffic.pcap"
```

**Cách 2: Dùng script test**
```bash
python test_pcap_endpoint.py /tmp/traffic.pcap
```

**Cách 3: Dùng Python script**
```bash
python wireshark_to_api.py /tmp/traffic.pcap
```

---

## 📊 Đọc kết quả

```
✅ Flow 1: Benign (Confidence: High)     ← Traffic bình thường
⚠️ Flow 2: Attack (Confidence: High)    ← Phát hiện tấn công!

📊 Summary:
   Total flows: 132
   Attacks: 0         ← Số lượng tấn công phát hiện
   Benign: 132        ← Traffic an toàn
   Attack rate: 0.0%  ← Tỷ lệ tấn công
```

---

## 🔧 Troubleshooting

| Vấn đề | Giải pháp |
|--------|-----------|
| `No such device` | Interface sai → Chạy `ip link show` |
| `Permission denied` | Chạy API với `sudo python api.py` hoặc set capabilities |
| `Cannot connect to API` | Chạy `python api.py` trong terminal khác |
| `PyShark not installed` | Cài: `pip install pyshark` |
| `tshark not found` | Cài: `sudo apt install tshark` (cần cho pyshark) |

---

## 🎯 Bộ lọc hữu ích (dùng với display_filter)

```bash
# Chỉ capture web traffic (HTTP/HTTPS)
curl -X POST "http://localhost:8000/capture/live" \
  -H "Content-Type: application/json" \
  -d '{"interface": "wlp2s0", "duration": 60, "display_filter": "tcp port 80 or tcp port 443"}'

# Chỉ capture DNS queries
curl -X POST "http://localhost:8000/capture/live" \
  -H "Content-Type: application/json" \
  -d '{"interface": "wlp2s0", "duration": 60, "display_filter": "udp port 53"}'

# Capture traffic đến IP cụ thể
curl -X POST "http://localhost:8000/capture/live" \
  -H "Content-Type: application/json" \
  -d '{"interface": "wlp2s0", "duration": 60, "display_filter": "host 192.168.1.1"}'
```

---

## 📝 One-liner (Copy & paste)

```bash
# Capture 50 gói và phân tích ngay (KHÔNG CẦN TSHARK, KHÔNG CẦN CHỈ ĐỊNH INTERFACE!)
curl -X POST "http://localhost:8000/capture/live" \
  -H "Content-Type: application/json" \
  -d '{"packet_count": 50}'
```

## 🔄 So sánh: Cách cũ vs Cách mới

### ❌ Cách cũ (dùng tshark command line)
```bash
# Bước 1: Capture
sudo tshark -i wlp2s0 -a duration:60 -w /tmp/traffic.pcap
sudo chmod 644 /tmp/traffic.pcap

# Bước 2: Phân tích
python test_pcap_endpoint.py /tmp/traffic.pcap

# Bước 3: Xóa file tạm
rm /tmp/traffic.pcap
```

### ✅ Cách mới (dùng API - Đơn giản nhất!)
```bash
# Chỉ 1 bước: Capture và phân tích ngay (tự động chọn interface!)
curl -X POST "http://localhost:8000/capture/live" \
  -H "Content-Type: application/json" \
  -d '{"duration": 60}'
```

**Lợi ích:**
- ✅ Không cần file tạm
- ✅ Không cần tshark command line
- ✅ **Không cần chỉ định interface** - tự động chọn!
- ✅ Tự động phân tích ngay sau khi capture
- ✅ Dễ tích hợp vào ứng dụng khác
