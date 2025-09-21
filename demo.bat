@echo off
echo 🎯 PhishRadar Demo - Vietnamese Phishing Detection
echo =====================================================

echo 🔍 Checking available options...

:: Check if .NET 8 is available
dotnet --version >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ .NET 8 SDK found
    set HAS_DOTNET=1
) else (
    echo ❌ .NET 8 SDK not found
    set HAS_DOTNET=0
)

:: Check if Docker is available
docker --version >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Docker found
    set HAS_DOCKER=1
) else (
    echo ❌ Docker not found
    set HAS_DOCKER=0
)

echo.
echo 📋 Available demo options:
if %HAS_DOTNET%==1 echo    1. .NET Direct (Fastest)
if %HAS_DOCKER%==1 echo    2. Docker (Professional)
echo    3. Download dependencies
echo    4. Exit

echo.
set /p choice="Choose option (1-4): "

if "%choice%"=="1" goto dotnet_demo
if "%choice%"=="2" goto docker_demo
if "%choice%"=="3" goto install_deps
if "%choice%"=="4" goto end

:: Invalid choice
echo Invalid choice. Trying .NET direct...

:dotnet_demo
if %HAS_DOTNET%==0 (
    echo ❌ .NET 8 SDK required. Choose option 3 to install.
    pause
    goto end
)

echo 🚀 Starting PhishRadar with .NET Direct...
cd src\Api
start dotnet run
echo ⏳ Waiting for API to start...
timeout /t 10

echo ✅ API should be running at http://localhost:5122
echo 🧪 Run test.bat for quick tests
pause
goto end

:docker_demo
if %HAS_DOCKER%==0 (
    echo ❌ Docker required. Choose option 3 to install.
    pause
    goto end
)

echo 🐳 Building Docker image...
docker build -t phishradar .

if %errorlevel% neq 0 (
    echo ❌ Docker build failed!
    pause
    goto end
)

echo 🚀 Starting PhishRadar container...
docker run -d -p 5122:5122 --name phishradar-demo phishradar

echo ⏳ Waiting for container to start...
timeout /t 15

echo ✅ Container should be running at http://localhost:5122
echo 🧪 Run test.bat for quick tests
echo 🛑 To stop: docker stop phishradar-demo && docker rm phishradar-demo
pause
goto end

:install_deps
echo 📥 Installation links:
echo.
echo .NET 8 SDK:
echo https://dotnet.microsoft.com/download/dotnet/8.0
echo.
echo Docker Desktop:
echo https://www.docker.com/products/docker-desktop/
echo.
echo Visual Studio 2022 Community (Free):
echo https://visualstudio.microsoft.com/vs/community/
echo.
echo After installation, run demo.bat again
pause
goto end

:end
echo.
echo 👋 PhishRadar Demo Complete!
echo 📖 See DOCKER_DEMO.md for detailed instructions
echo 📞 Support: GitHub Issues