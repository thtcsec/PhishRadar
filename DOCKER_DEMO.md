# 🐳 PhishRadar Demo - Multiple Options

## 🚀 **Option 1: Không cần Docker (Fastest)**

### Yêu cầu
- .NET 8 SDK (download từ microsoft.com/dotnet)
- Git

### Demo nhanh
```bash
# Clone repo
git clone https://github.com/thtcsec/PhishRadar.git
cd PhishRadar

# Chạy trực tiếp
cd src/Api
dotnet run

# Test (terminal khác)
curl http://localhost:5122/health
```

⏱️ **Thời gian**: ~2 phút (nếu có .NET 8)

---

## 🐳 **Option 2: Docker (Professional)**

### Yêu cầu
- Docker Desktop installed
- Git

### Cài Docker nhanh (Windows)
```bash
# Download Docker Desktop từ:
https://www.docker.com/products/docker-desktop/

# Hoặc winget (nếu có)
winget install Docker.DockerDesktop
```

### Demo với Docker
```bash
# Clone repo
git clone https://github.com/thtcsec/PhishRadar.git
cd PhishRadar

# Option 2A: Script tự động
demo.bat

# Option 2B: Manual
docker build -t phishradar .
docker run -d -p 5122:5122 --name phishradar-demo phishradar

# Test
curl http://localhost:5122/health
```

⏱️ **Thời gian**: ~5 phút (build + run)

---

## 💻 **Option 3: Visual Studio (For Developers)**

### Yêu cầu
- Visual Studio 2022 (Community free)
- Git

### Demo với VS
```bash
# Clone repo
git clone https://github.com/thtcsec/PhishRadar.git

# Mở trong Visual Studio
PhishRadar.sln

# Press F5 (Start Debugging)
# API sẽ chạy tại http://localhost:5122
```

⏱️ **Thời gian**: ~1 phút (fastest)

---

## 🧪 **Test Cases (All Options)**

Sau khi API chạy (bất kể option nào), test với:

### 1. Health check
```bash
curl http://localhost:5122/health
```

### 2. Vietnamese banking phishing
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://vietcom-bank.tk/verify"}'
```

### 3. Vietnamese gambling
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://nohu88.club"}'
```

### 4. Safe educational site
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://huflit.edu.vn"}'
```

### 5. API information
```bash
curl http://localhost:5122/api-info
```

---

## 📊 **Expected Results**

### Phishing (Risk 80-95):
```json
{
  "risk": 85,
  "reasons": ["🚨 FAKE: Vietnamese bank domain pattern"],
  "recommendations": ["🚨 HIGH RISK - Do not enter personal information"]
}
```

### Gambling (Risk 90-95):
```json
{
  "risk": 90,
  "reasons": ["🇻🇳 Vietnamese gambling site detected"],
  "recommendations": ["🎰 Online gambling is illegal in Vietnam"]
}
```

### Safe (Risk 0-20):
```json
{
  "risk": 0,
  "tags": ["whitelisted"],
  "recommendations": ["✅ Legitimate educational website detected"]
}
```

---

## 🛑 **Stop Demo**

### .NET Direct:
```bash
Ctrl+C trong terminal
```

### Docker:
```bash
docker stop phishradar-demo
docker rm phishradar-demo
```

### Visual Studio:
```
Shift+F5 hoặc đóng VS
```

---

## 🚨 **Troubleshooting**

### "dotnet command not found"
```bash
# Download .NET 8 SDK từ:
https://dotnet.microsoft.com/download/dotnet/8.0
```

### "Docker not found"
```bash
# Download Docker Desktop từ:
https://www.docker.com/products/docker-desktop/
```

### "Port 5122 already in use"
```bash
# Kill process sử dụng port 5122
netstat -ano | findstr :5122
taskkill /PID <PID> /F
```

### "curl not found" (Windows)
```bash
# Sử dụng PowerShell:
Invoke-WebRequest http://localhost:5122/health

# Hoặc browser:
http://localhost:5122/health
```

---

## 💡 **Recommendation cho Giám khảo**

### 🥇 **Fastest**: Visual Studio (nếu có sẵn)
### 🥈 **Easiest**: .NET CLI (`dotnet run`)  
### 🥉 **Most Professional**: Docker

**Chọn option phù hợp với setup hiện tại!**

---
*Demo PhishRadar v5.0 - True AI Intelligence for Vietnamese Market*