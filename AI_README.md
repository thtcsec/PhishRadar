# PhishRadar AI System 🤖

Advanced AI-powered phishing detection system for Vietnamese market with multiple machine learning models and ensemble intelligence.

## 🎯 Features

### Multiple AI Models
- **LightGBM**: Best performance for tabular data
- **FastTree**: Fast and accurate decision trees  
- **Logistic Regression**: Interpretable linear model
- **Neural Network**: Deep learning capabilities
- **Ensemble Model**: Combines all models for best accuracy

### Advanced Capabilities
- **Real-time Inference**: ONNX runtime for fast predictions
- **Feature Engineering**: 24+ advanced features extraction
- **Explainable AI**: SHAP-like feature contributions
- **Vietnamese Context**: Specialized for VN phishing patterns
- **Intelligent Fallback**: Works even without models
- **Performance Caching**: 5-minute result caching

## 🚀 Quick Start

### 1. Train AI Models

```bash
# Windows
scripts\deploy-ai.bat

# Linux/Mac  
chmod +x scripts/deploy-ai.sh
./scripts/deploy-ai.sh
```

### 2. Manual Training

```bash
cd src/PhishRadar.Training
dotnet run
```

### 3. Evaluate Models

```bash
cd src/PhishRadar.Training
dotnet run -- --eval
```

### 4. Quick Test

```bash
cd src/PhishRadar.Training  
dotnet run -- --test
```

### 5. Start API with AI

```bash
cd src/Api
dotnet run
```

## 📊 AI Model Architecture

### Feature Engineering (24 Features)
```
Basic Features (7):
- UrlLength, HasAt, HasHyphen, NumDigits
- IsHttp, ContainsOtpKeyword, ContainsBankKeyword

Advanced Features (17):  
- HostLength, PathLength, SubdomainCount
- HasSuspiciousTld, HasPunycode, UrlEntropy
- FormCount, InputCount, LinkCount, ScriptCount
- HasUrgencyKeywords, HasVietnameseKeywords
- IsVietnameseBankDomain, HasGamblingKeywords
- IsEducationalDomain, PathDepth, HasSensitiveKeywords
```

### Model Pipeline
```
Input URL → Feature Extraction → Multiple Models → Ensemble → Risk Score
                                     ↓
                           [LightGBM, FastTree, Logistic, Neural]
                                     ↓
                           Weighted Average + Confidence
                                     ↓
                              Final Risk Score (0-100%)
```

## 🔬 Model Performance

### Typical Accuracy Rates
- **LightGBM**: ~94% accuracy on test data
- **FastTree**: ~92% accuracy on test data  
- **Logistic**: ~89% accuracy on test data
- **Ensemble**: ~96% accuracy (combined)

### Benchmark Performance
- **Inference Speed**: ~2-5ms per prediction
- **Throughput**: ~500-1000 predictions/second
- **Memory Usage**: ~50-100MB for all models

## 🛠️ API Integration

### Basic Scoring
```csharp
// In your service
public class PhishingService
{
    private readonly IMlScorer _aiService;
    
    public async Task<double> GetRiskScore(string url)
    {
        var features = AIFeatureExtractor.ExtractAdvancedFeatures(url);
        return await _aiService.ScoreAsync(features.ToArray());
    }
}
```

### Advanced Scoring with Explainability
```csharp
public async Task<AIResult> GetDetailedAnalysis(string url)
{
    var features = ExtractAdvancedFeatures(url);
    var (score, contributions) = await _aiService
        .ScoreAdvancedWithExplainabilityAsync(features);
        
    return new AIResult 
    { 
        Risk = (int)(score * 100),
        TopFactors = contributions.Take(5).ToList()
    };
}
```

## 📈 Model Training Data

### CSV Format
```csv
Label,UrlLength,HasAt,HasHyphen,NumDigits,IsHttp,ContainsOtpKeyword,ContainsBankKeyword
1,89,0,3,12,1,1,1
0,42,0,1,2,0,0,0
```

### Adding Training Data
1. Add samples to `src/PhishRadar.Training/data/phish_data.csv`
2. Run training: `dotnet run`
3. Deploy models: `scripts/deploy-ai.bat`

## 🎯 Vietnamese Specialization

### Banking Detection
- All major VN banks: VietcomBank, TechcomBank, BIDV, ACB, etc.
- Domain patterns: `.com.vn` vs `.xyz`, `.tk`
- Vietnamese phishing keywords

### Gambling Detection  
- Vietnamese gambling terms: "nổ hũ", "tài xỉu", "cờ bạc"
- Illegal gambling sites detection
- Cultural context awareness

### Educational Whitelist
- `.edu.vn`, `.ac.vn` domains
- Reduced false positives for universities
- Government domain handling

## 🔧 Configuration

### Environment Variables
```bash
# Model path (optional)
PHISHRADAR_MODELS_PATH=/path/to/models

# Cache settings
PHISHRADAR_CACHE_MINUTES=5
PHISHRADAR_MAX_CACHE_SIZE=1000
```

### Dependency Injection (API)
```csharp
// Use Production AI Service
builder.Services.AddSingleton<IMlScorer, ProductionAIService>();

// Use Enhanced ML Scorer (fallback)
builder.Services.AddSingleton<IMlScorer, EnhancedMlScorer>();
```

## 🚨 Troubleshooting

### Models Not Loading
```
⚠️ ONNX model not found, using intelligent fallback
```
**Solution**: Run training script or copy .onnx files to API directory

### Low Performance
```
💾 High memory usage detected
```
**Solution**: Enable cache cleanup or reduce model count

### Training Errors
```
❌ Training failed!
```
**Solution**: Check data format, install ML.NET packages

## 📚 API Endpoints

### Health Check with AI Status
```bash
curl http://localhost:5122/health
```

Response:
```json
{
  "status": "healthy",
  "version": "4.0.0-production-ai",
  "ai": {
    "status": "production_ensemble", 
    "models": 4,
    "cacheEntries": 150
  }
}
```

### Scan with AI Analysis
```bash
curl -X POST http://localhost:5122/score \
  -H "Content-Type: application/json" \
  -d '{"url":"http://fake-bank.xyz/otp"}'
```

Response includes AI explainability:
```json
{
  "risk": 85,
  "explainability": {
    "algorithm": "Production AI Ensemble + Rules Hybrid",
    "featureContributions": ["HTTP_Protocol:+0.35", "Banking_Keywords:+0.45"],
    "aiInsights": ["🤖 AI: High confidence based on learned patterns"]
  }
}
```

## 🔮 Future Enhancements

- **Transformer Models**: BERT for Vietnamese text analysis
- **Real-time Learning**: Online model updates
- **Graph Neural Networks**: Domain relationship analysis  
- **Computer Vision**: Logo/visual similarity detection
- **Federated Learning**: Privacy-preserving model updates

## 📄 License


---

**Made with ❤️ **