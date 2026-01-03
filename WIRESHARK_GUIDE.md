# 🦈 Wireshark Integration Guide

Hướng dẫn đơn giản nhất để phân tích network traffic với IoT Attack Detector.

---

## 🚀 Quick Start (3 bước đơn giản)

### Bước 1: Chạy API
```bash
python api.py
```

### Bước 2: Capture traffic
```bash
# Tìm tên interface của bạn
ip link show

# Capture 60 giây (thay wlp2s0 bằng interface của bạn)
sudo tshark -i wlp2s0 -a duration:60 -w /tmp/traffic.pcap
sudo chmod 644 /tmp/traffic.pcap
```

### Bước 3: Phân tích
```bash
python test_pcap_endpoint.py /tmp/traffic.pcap
```

**Xong!** 🎉

---

## 📋 Chi tiết từng bước

### 1️⃣ Tìm tên giao diện mạng

```bash
ip link show
```

Output ví dụ:
- `wlp2s0` ← Wi-Fi (dùng cái này nếu bạn dùng Wi-Fi)
- `eth0` hoặc `enp3s0` ← Ethernet
- `lo` ← Loopback (không dùng)

### 2️⃣ Capture network packets

**Cách 1: Capture trong thời gian cố định**
```bash
sudo tshark -i wlp2s0 -a duration:60 -w /tmp/traffic.pcap
sudo chmod 644 /tmp/traffic.pcap
```

**Cách 2: Capture số gói cụ thể**
```bash
sudo tshark -i wlp2s0 -c 100 -w /tmp/traffic.pcap
sudo chmod 644 /tmp/traffic.pcap
```

### 3️⃣ Phân tích file PCAP

**Cách 1: Dùng script test (Đơn giản nhất ✅)**
```bash
python test_pcap_endpoint.py /tmp/traffic.pcap
```

**Cách 2: Dùng Python script**
```bash
python wireshark_to_api.py /tmp/traffic.pcap
```

**Cách 3: Dùng curl để upload**
```bash
curl -X POST "http://localhost:8000/analyze/pcap" \
  -F "file=@/tmp/traffic.pcap"
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
| `Permission denied` | Thêm `sudo` khi capture |
| `Cannot connect to API` | Chạy `python api.py` trong terminal khác |
| `tshark not found` | Cài: `sudo apt install tshark` |

---

## 🎯 Bộ lọc hữu ích

```bash
# Chỉ capture web traffic (HTTP/HTTPS)
sudo tshark -i wlp2s0 -a duration:60 \
  -f "tcp port 80 or tcp port 443" -w /tmp/web.pcap

# Chỉ capture DNS queries
sudo tshark -i wlp2s0 -a duration:60 \
  -f "udp port 53" -w /tmp/dns.pcap

# Capture traffic đến IP cụ thể
sudo tshark -i wlp2s0 -a duration:60 \
  -f "host 192.168.1.1" -w /tmp/target.pcap
```

---

## 📝 One-liner (Copy & paste)

```bash
# Capture 50 gói và phân tích ngay
sudo tshark -i wlp2s0 -c 50 -w /tmp/test.pcap && \
sudo chmod 644 /tmp/test.pcap && \
python test_pcap_endpoint.py /tmp/test.pcap
```
