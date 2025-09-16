@echo off
echo ====================================
echo    PHISHRADAR AI TRAINING SCRIPT
echo ====================================
echo.

cd /d "%~dp0..\src\PhishRadar.Training"

echo [INFO] Current directory: %CD%
echo [INFO] Starting AI model training...
echo.

REM Train all models
echo [STEP 1] Training all AI models...
dotnet run
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Training failed!
    pause
    exit /b 1
)

echo.
echo [STEP 2] Running quick test...
dotnet run -- --test
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Quick test failed!
    pause
    exit /b 1
)

echo.
echo [STEP 3] Running full evaluation...
dotnet run -- --eval
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Evaluation failed!
    pause
    exit /b 1
)

echo.
echo ====================================
echo    AI TRAINING COMPLETED SUCCESS!
echo ====================================
echo.
echo Models generated:
echo   - phishradar.onnx (Main model)
echo   - phishradar_sophisticated.zip (30-feature model)
echo   - phishradar_lightgbm.onnx (LightGBM)
echo   - phishradar_fasttree.onnx (FastTree)
echo   - phishradar_logistic.onnx (Logistic Regression)
echo.
echo Press any key to exit...
pause > nul