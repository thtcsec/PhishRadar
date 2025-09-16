@echo off
echo ====================================
echo     PHISHRADAR DEMO & TEST SCRIPT
echo ====================================
echo.

cd /d "%~dp0..\src\PhishRadar.Training"

echo [INFO] Running sophisticated AI tests...
echo.

echo [TEST 1] Quick intelligence test...
dotnet run -- --test
echo.

echo [TEST 2] Full evaluation with performance benchmarks...
dotnet run -- --eval
echo.

echo ====================================
echo          STARTING API SERVER
echo ====================================
echo.

cd ..\Api
echo [INFO] Starting PhishRadar API server...
echo [INFO] API will be available at: http://localhost:5122
echo [INFO] Health check: http://localhost:5122/health
echo.
echo Press Ctrl+C to stop the server
echo.
dotnet run