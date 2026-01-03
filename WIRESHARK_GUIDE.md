# 🦈 Wireshark Integration Guide

Hướng dẫn đơn giản để sử dụng Wireshark với IoT Attack Detector.

---

## Step 1: Cài đặt công cụ cần thiết

```bash
# Cài Wireshark và tshark
sudo apt update
sudo apt install wireshark tshark

# Cài Python dependencies
pip install scapy pandas requests
```

---

## Step 2: Tìm tên giao diện mạng

```bash
ip link show
```

Ví dụ output:
- `wlp2s0` - Wi-Fi
- `eth0` hoặc `enp3s0` - Ethernet
- `lo` - Loopback (không dùng)

---

## Step 3: Capture Network Traffic

### Option A: Dùng tshark (Khuyến nghị)

```bash
# Capture 60 giây trên Wi-Fi, lưu vào /tmp để tránh lỗi permission
sudo tshark -i wlp2s0 -a duration:60 -w /tmp/traffic.pcap

# Đổi quyền để Python có thể đọc file
sudo chmod 644 /tmp/traffic.pcap
```

### Option B: Capture số gói cụ thể

```bash
# Capture 100 gói
sudo tshark -i wlp2s0 -c 100 -w /tmp/traffic.pcap
sudo chmod 644 /tmp/traffic.pcap
```

### Option C: Dùng Wireshark GUI

1. Mở Wireshark
2. Chọn interface (ví dụ: `wlp2s0`)
3. Click nút shark xanh để bắt đầu
4. Dừng khi xong
5. Save: `File > Save As > traffic.pcap`

---

## Step 4: Phân tích traffic

```bash
# Đảm bảo API đang chạy (Terminal 1)
python api.py

# Phân tích file pcap (Terminal 2)
python wireshark_to_api.py /tmp/traffic.pcap
```

---

## Step 5: Đọc kết quả

```
✅ Flow 1: Benign (Confidence: High)    ← Traffic bình thường
⚠️ Flow 2: Attack (Confidence: High)   ← Phát hiện tấn công!
```

---

## 🚀 Quick Test (Copy & Paste)

```bash
# Terminal 1: Chạy API
python api.py

# Terminal 2: Capture và phân tích
sudo tshark -i wlp2s0 -c 50 -w /tmp/test.pcap && \
sudo chmod 644 /tmp/test.pcap && \
python wireshark_to_api.py /tmp/test.pcap
```

---

## 🔧 Troubleshooting

| Lỗi | Giải pháp |
|-----|-----------|
| `No such device` | Chạy `ip link show` để tìm tên interface đúng |
| `Permission denied` (capture) | Lưu vào `/tmp/` thay vì thư mục hiện tại |
| `Permission denied` (read) | Chạy `sudo chmod 644 /tmp/file.pcap` |
| `Cannot connect to API` | Đảm bảo `python api.py` đang chạy |
| `tshark not found` | Cài đặt: `sudo apt install tshark` |

---

## 📚 Bộ lọc hữu ích

```bash
# Chỉ capture HTTP/HTTPS (web traffic)
sudo tshark -i wlp2s0 -a duration:60 -f "tcp port 80 or tcp port 443" -w /tmp/web.pcap

# Chỉ capture DNS
sudo tshark -i wlp2s0 -a duration:60 -f "udp port 53" -w /tmp/dns.pcap

# Capture tới IP cụ thể
sudo tshark -i wlp2s0 -a duration:60 -f "host 192.168.1.1" -w /tmp/target.pcap
```
