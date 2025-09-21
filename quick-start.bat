@echo off
echo 🚀 PhishRadar Quick Start - .NET Direct
echo =====================================

echo 🔍 Checking .NET 8...
dotnet --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ .NET 8 SDK not found!
    echo 📥 Download from: https://dotnet.microsoft.com/download/dotnet/8.0
    pause
    exit /b 1
)

echo ✅ .NET 8 found, starting API...

cd src\Api
echo 🚀 Running: dotnet run
echo 📡 API will be at: http://localhost:5122

start dotnet run

echo ⏳ Waiting for API to start...
timeout /t 10

echo.
echo ✅ PhishRadar API should be running!
echo 🧪 Test commands:
echo    curl http://localhost:5122/health
echo    test.bat
echo.
echo 🛑 To stop: Press Ctrl+C in the API window
pause