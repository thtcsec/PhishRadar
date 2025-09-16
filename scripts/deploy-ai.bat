@echo off
echo 🤖 PhishRadar AI Training ^& Deployment Pipeline
echo ==============================================

REM Step 1: Build Training Project
echo 📦 Building Training Project...
cd src\PhishRadar.Training
dotnet build --configuration Release

if %ERRORLEVEL% NEQ 0 (
    echo ❌ Build failed!
    exit /b 1
)

REM Step 2: Run AI Training
echo 🧠 Training AI Models...
dotnet run --configuration Release

if %ERRORLEVEL% NEQ 0 (
    echo ❌ Training failed!
    exit /b 1
)

REM Step 3: Copy models to API project
echo 📋 Deploying Models to API...
cd ..\..\

REM Create models directory in API project
if not exist "src\Api\models" mkdir "src\Api\models"
if not exist "src\Rules\models" mkdir "src\Rules\models"

REM Copy all ONNX models
copy "src\PhishRadar.Training\bin\Release\net8.0\*.onnx" "src\Api\models\" >nul 2>&1
copy "src\PhishRadar.Training\bin\Release\net8.0\*.onnx" "src\Rules\models\" >nul 2>&1

echo ✅ Models deployed successfully!

REM Step 4: Build API with new models
echo 🚀 Building API with AI Models...
cd src\Api
dotnet build --configuration Release

if %ERRORLEVEL% NEQ 0 (
    echo ❌ API build failed!
    exit /b 1
)

REM Step 5: Run Tests
echo 🧪 Running Tests...
cd ..\..\tests\UnitTests
dotnet test --configuration Release

REM Step 6: Show deployment summary
echo 🎉 AI Deployment Complete!
echo Available AI Models:
dir "..\..\src\Api\models\*.onnx" 2>nul

echo.
echo To start the API with AI:
echo cd src\Api ^&^& dotnet run
echo.
echo AI Health Check:
echo curl http://localhost:5122/health