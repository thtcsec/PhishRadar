# PhishRadar - Vietnamese Phishing Detection

Hệ thống phát hiện phishing chuyên biệt cho thị trường Việt Nam với AI thông minh.

## 🐳 **Demo nhanh với Docker**

```bash
docker build -t phishradar .
docker run --rm -p 5122:5122 phishradar
curl -s http://localhost:5122/health
```

## ✨ Tính năng chính

- **AI thông minh**: Machine learning thực sự (không phải hardcode)
- **Chuyên biệt VN**: Phát hiện lừa đảo ngân hàng, cờ bạc Việt Nam
- **Hiệu suất cao**: API nhanh, cache thông minh
- **Dễ tích hợp**: REST API đơn giản

## 🚀 Cài đặt nhanh

### Option 1: Docker (Recommended cho demo)
```bash
# Clone repository
git clone https://github.com/thtcsec/PhishRadar.git
cd PhishRadar

# Demo 1-click
demo.bat  # Windows

# Hoặc manual
docker build -t phishradar .
docker run -p 5122:5122 phishradar
```

### Option 2: .NET Development
```bash
# Clone repository
git clone https://github.com/thtcsec/PhishRadar.git
cd PhishRadar

# Setup training data (optional - có sample data sẵn)
setup.bat

# Chạy API
cd src/Api
dotnet run

# Test
curl http://localhost:5122/health
```

## 📊 Test cases

### Kiểm tra Vietnamese banking phishing
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://vietcom-bank.tk/verify"}'
```

### Phản hồi
```json
{
  "risk": 85,
  "reasons": ["🚨 FAKE: Vietnamese bank domain pattern", "⚠️ HTTP protocol"],
  "recommendations": ["🚨 HIGH RISK - Do not enter personal information"]
}
```

### Test Vietnamese gambling
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://nohu88.club"}'
```

### Test safe site
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://huflit.edu.vn"}'
```

## 🤖 Nâng cấp AI

### Demo (sử dụng sample data có sẵn):
```bash
cd src/PhishRadar.Training
python train_true_ai.py  # Sử dụng sample_data.csv

# Copy models về API
copy production_models\*.onnx ..\Api\production_models\
```

### Production (tải data thật):
```bash
# Cài Python ML + tải data lớn
setup.bat

# Train với data thật
cd src/PhishRadar.Training
python train_true_ai.py
```

## 🇻🇳 Đặc biệt cho Việt Nam

- Phát hiện fake banking: vietcombank, techcombank, bidv...
- Phát hiện cờ bạc: nổ hũ, game bài, cá độ...
- Ngôn ngữ Việt: "khẩn cấp", "xác thực", "hết hạn"...
- TLD nguy hiểm: .tk, .ml, .xyz với nội dung VN

## 📁 Cấu trúc

```
src/
├── Api/           # REST API
├── Core/          # Models & interfaces  
├── Rules/         # Detection rules & AI
├── Infrastructure/# External services
└── PhishRadar.Training/  
    ├── sample_data.csv      # Demo data (10 samples)
    ├── train_true_ai.py     # AI training script
    └── data_sources/        # Real data (via setup.bat)
```

## 🛡️ Production

- ✅ .NET 8
- ✅ Docker ready
- ✅ Cache thông minh
- ✅ Error handling
- ✅ Health monitoring
- ✅ Async/await

## 📖 Chi tiết

- [USAGE.md](USAGE.md) - Hướng dẫn API đầy đủ
- [DOCKER_DEMO.md](DOCKER_DEMO.md) - Demo cho giám khảo

## 📞 Hỗ trợ

- Issues: GitHub Issues
- Email: support@thtcsec.com
- Vietnamese market focus

---
*PhishRadar v5.0 - True AI Intelligence*