@echo off
echo 🧪 PhishRadar Quick Test - for Judges
echo ====================================

echo 📡 Testing API endpoints...

echo.
echo 1️⃣ Health Check:
curl -s http://localhost:5122/health | jq .

echo.
echo 2️⃣ API Info:
curl -s http://localhost:5122/api-info | jq .

echo.
echo 3️⃣ Vietnamese Banking Phishing:
curl -s -X POST http://localhost:5122/score -H "Content-Type: application/json" -d "{\"url\":\"http://vietcom-bank.tk/verify\"}" | jq .

echo.
echo 4️⃣ Vietnamese Gambling:
curl -s -X POST http://localhost:5122/score -H "Content-Type: application/json" -d "{\"url\":\"http://nohu88.club\"}" | jq .

echo.
echo 5️⃣ Safe Educational Site:
curl -s -X POST http://localhost:5122/score -H "Content-Type: application/json" -d "{\"url\":\"http://huflit.edu.vn\"}" | jq .

echo.
echo ✅ Test complete! 
echo 📊 Expected: High risk for phishing/gambling, Low risk for educational
pause