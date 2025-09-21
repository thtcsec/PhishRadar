# PhishRadar - Vietnamese Phishing Detection

Hệ thống phát hiện phishing chuyên biệt cho thị trường Việt Nam với AI thông minh.

## 🚀 **Demo nhanh - Multiple Options**

### Option 1: .NET Direct (Fastest)
```bash
# Yêu cầu: .NET 8 SDK
git clone https://github.com/thtcsec/PhishRadar.git
cd PhishRadar
quick-start.bat  # Windows auto-start
```

### Option 2: Docker (Professional)
```bash
# Yêu cầu: Docker Desktop
docker build -t phishradar .
docker run --rm -p 5122:5122 phishradar
curl -s http://localhost:5122/health
```

### Option 3: Smart Demo (Detects tools)
```bash
git clone https://github.com/thtcsec/PhishRadar.git
cd PhishRadar
demo.bat  # Tự động detect .NET/Docker
```

## ✨ Tính năng chính

- **AI thông minh**: Machine learning thực sự (không phải hardcode)
- **Chuyên biệt VN**: Phát hiện lừa đảo ngân hàng, cờ bạc Việt Nam
- **Hiệu suất cao**: API nhanh, cache thông minh
- **Dễ tích hợp**: REST API đơn giản

## 📊 Test cases nhanh

### Vietnamese banking phishing
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://vietcom-bank.tk/verify"}'
```
→ **Expected**: Risk 85+ (HIGH RISK)

### Vietnamese gambling
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://nohu88.club"}'
```
→ **Expected**: Risk 90+ (GAMBLING DETECTED)

### Safe educational site
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://huflit.edu.vn"}'
```
→ **Expected**: Risk 0 (SAFE)

## 🧪 **Automated Testing**
```bash
test.bat  # Chạy tất cả test cases
```

## 🔧 **Nếu thiếu dependencies**

### .NET 8 SDK
```
https://dotnet.microsoft.com/download/dotnet/8.0
```

### Docker Desktop
```
https://www.docker.com/products/docker-desktop/
```

### Visual Studio 2022 (Free)
```
https://visualstudio.microsoft.com/vs/community/
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
- ✅ Multiple deployment options
- ✅ Cache thông minh
- ✅ Error handling
- ✅ Health monitoring
- ✅ Async/await

## 📖 Chi tiết

- [DOCKER_DEMO.md](DOCKER_DEMO.md) - Demo options cho giám khảo
- [USAGE.md](USAGE.md) - Hướng dẫn API đầy đủ

## 📞 Hỗ trợ

- Issues: GitHub Issues
- Email: support@thtcsec.com
- Vietnamese market focus

---
*PhishRadar v5.0 - True AI Intelligence*