# 🐳 PhishRadar Docker Demo

## Yêu cầu
- Docker Desktop installed
- Git (để clone repo)

## Demo nhanh (1-click)

### Option 1: Script tự động
```bash
# Clone repo
git clone https://github.com/thtcsec/PhishRadar.git
cd PhishRadar

# Chạy demo (Windows)
demo.bat
```

### Option 2: Manual
```bash
# Build image
docker build -t phishradar .

# Run container
docker run -d -p 5122:5122 --name phishradar-demo phishradar

# Test API
curl http://localhost:5122/health
```

### Option 3: Docker Compose
```bash
# Start với docker-compose
docker-compose up -d

# Test
curl http://localhost:5122/health
```

## 🧪 Test cases cho giám khảo

### 1. Health check
```bash
curl http://localhost:5122/health
```

### 2. API information
```bash
curl http://localhost:5122/api-info
```

### 3. Vietnamese banking phishing
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://vietcom-bank.tk/verify"}'
```

### 4. Vietnamese gambling
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://nohu88.club"}'
```

### 5. Safe site
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url": "http://huflit.edu.vn"}'
```

## 📊 Expected Results

### Phishing (Risk 80-95):
```json
{
  "risk": 85,
  "reasons": ["🚨 FAKE: Vietnamese bank domain pattern"],
  "recommendations": ["🚨 HIGH RISK - Do not enter personal information"]
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

## 🛑 Stop demo
```bash
docker stop phishradar-demo
docker rm phishradar-demo
```

---
*Demo PhishRadar v5.0 - True AI Intelligence for Vietnamese Market*