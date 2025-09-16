#!/bin/bash

echo "🤖 PhishRadar AI Training & Deployment Pipeline"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Step 1: Build Training Project
echo -e "${BLUE}📦 Building Training Project...${NC}"
cd src/PhishRadar.Training
dotnet build --configuration Release

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Build failed!${NC}"
    exit 1
fi

# Step 2: Run AI Training
echo -e "${BLUE}🧠 Training AI Models...${NC}"
dotnet run --configuration Release

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Training failed!${NC}"
    exit 1
fi

# Step 3: Copy models to API project
echo -e "${BLUE}📋 Deploying Models to API...${NC}"
cd ../../

# Create models directory in API project
mkdir -p src/Api/models

# Copy all ONNX models
cp src/PhishRadar.Training/bin/Release/net8.0/*.onnx src/Api/models/
cp src/PhishRadar.Training/bin/Release/net8.0/*.onnx src/Rules/models/ 2>/dev/null || mkdir -p src/Rules/models && cp src/PhishRadar.Training/bin/Release/net8.0/*.onnx src/Rules/models/

echo -e "${GREEN}✅ Models deployed successfully!${NC}"

# Step 4: Build API with new models
echo -e "${BLUE}🚀 Building API with AI Models...${NC}"
cd src/Api
dotnet build --configuration Release

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ API build failed!${NC}"
    exit 1
fi

# Step 5: Run Tests
echo -e "${BLUE}🧪 Running Tests...${NC}"
cd ../../tests/UnitTests
dotnet test --configuration Release

# Step 6: Show deployment summary
echo -e "${GREEN}🎉 AI Deployment Complete!${NC}"
echo -e "${YELLOW}Available AI Models:${NC}"
ls -la ../../src/Api/models/*.onnx 2>/dev/null || echo "No models found in API directory"

echo ""
echo -e "${YELLOW}To start the API with AI:${NC}"
echo "cd src/Api && dotnet run"
echo ""
echo -e "${YELLOW}AI Health Check:${NC}"
echo "curl http://localhost:5122/health"