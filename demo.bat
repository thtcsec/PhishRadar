@echo off
echo 🎯 PhishRadar Demo - Vietnamese Phishing Detection
echo =====================================================

echo 🐳 Building Docker image...
docker build -t phishradar .

if %errorlevel% neq 0 (
    echo ❌ Docker build failed! Make sure Docker is installed and running.
    pause
    exit /b 1
)

echo 🚀 Starting PhishRadar API...
docker run -d -p 5122:5122 --name phishradar-demo phishradar

echo ⏳ Waiting for API to start...
timeout /t 10

echo 🔍 Testing API health...
curl -s http://localhost:5122/health

echo.
echo ✅ PhishRadar Demo Ready!
echo 📡 API: http://localhost:5122
echo 📖 Health: http://localhost:5122/health  
echo 📊 API Info: http://localhost:5122/api-info

echo.
echo 🧪 Test Vietnamese phishing detection:
echo curl -X POST http://localhost:5122/score -H "Content-Type: application/json" -d "{\"url\":\"http://vietcom-bank.tk\"}"

echo.
echo 🛑 To stop demo: docker stop phishradar-demo && docker rm phishradar-demo
pause