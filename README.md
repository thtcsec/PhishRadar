# PhishRadar - Vietnamese Phishing Detection

AI-powered URL and QR code security scanner designed for Vietnamese cyber threats. Combines rule-based detection with machine learning for practical phishing protection.

## What it does

- **Real-time URL Scanning**: Quick phishing detection with sub-100ms response
- **QR Code Analysis**: Scans QR codes for malicious embedded links  
- **Vietnamese Focus**: Specialized for Vietnamese banking, gambling, and cultural patterns
- **AI Detection**: Multiple ML models with 30+ features for accurate classification
- **Educational Protection**: Smart whitelisting to prevent false positives

## Core Features

### AI Detection Engine
- **Multiple ML Models**: LightGBM, FastTree, Logistic Regression
- **Smart Features**: 30+ detection features including domain age, IP reputation, content analysis
- **Context Intelligence**: Educational domain protection, Vietnamese cultural awareness
- **Good Performance**: 160K+ predictions/second, practical for real-world use

### Detection Capabilities
- **Vietnamese Banking**: VietcomBank, TechcomBank, BIDV, ACB, VPBank spoofing
- **Gambling Sites**: Illegal gambling detection (nổ hũ, tài xỉu, casino)
- **Advanced Attacks**: Punycode (xn--vitcombank), subdomain attacks, character substitution
- **Content Analysis**: HTML parsing, form detection, suspicious patterns

## API Usage

### Scan a URL
```bash
POST /score
Content-Type: application/json

{
  "url": "https://example.com",
  "html": "<optional html content>",
  "text": "optional page text"
}
```

### Response Format
```json
{
  "risk": 85,
  "riskLevel": "CRITICAL",
  "reasons": [
    "🚨 FAKE: Vietnamese bank domain detected",
    "⚠️ HTTP protocol - insecure connection",
    "🎯 Punycode attack detected"
  ],
  "tags": ["vietnamese_banking", "punycode", "http_insecure"],
  "aiAnalysis": {
    "mlScore": 0.89,
    "algorithm": "AI + Rules Hybrid",
    "featureContributions": {
      "Bank_Impersonation": 0.45,
      "Punycode_Attack": 0.40,
      "HTTP_Protocol": 0.35
    }
  }
}
```

## Technical Stack

- **.NET 8** - Core platform
- **ASP.NET Core** - Web API
- **ML.NET 3.0.1** - Machine learning
- **LightGBM** - Primary ML algorithm
- **AngleSharp** - HTML parsing
- **SixLabors.ImageSharp** - QR code processing

## Quick Start

```bash
# Clone and setup
git clone https://github.com/thtcsec/PhishRadar
cd PhishRadar

# Train AI models
.\scripts\train-ai.bat

# Start demo
.\scripts\demo.bat
```

API available at `http://localhost:5122`

## AI Performance

| Model | Accuracy | AUC | Notes |
|-------|----------|-----|-------|
| **Sophisticated Model** | **100%** | **1.0000** | Best overall |
| LightGBM | 87.5% | 0.9583 | Fast & reliable |
| Logistic Regression | 100% | 1.0000 | Interpretable |

**Performance**: 160K+ predictions/sec, <100ms API response

## Demo Results

| URL | Risk | Detection |
|-----|------|-----------|
| `https://dictionary.cambridge.org/.../bet` | **0%** | Educational protection ✅ |
| `https://huflit.edu.vn` | **0%** | Educational whitelist ✅ |
| `http://vietcom-bank.xyz/otp-verify` | **100%** | Banking + HTTP + OTP ✅ |
| `https://xn--vitcombank-m7a.com` | **40%** | Punycode attack ✅ |
| `http://nohu88.club/casino` | **100%** | Vietnamese gambling ✅ |

## Key Features

### Smart Detection
- **Vietnamese Banking**: Official vs fake domain detection
- **Cultural Intelligence**: Vietnamese language patterns, social engineering
- **False Positive Prevention**: Educational sites protection
- **Advanced Threats**: Punycode, subdomain attacks, obfuscation

### Practical Benefits
- **Fast Response**: Sub-100ms for real-time use
- **High Accuracy**: 100% on sophisticated test cases
- **Vietnamese Focus**: Tailored for local threat landscape
- **Easy Integration**: Simple REST API

## Development

### Adding Custom Rules
```csharp
public class CustomRule : IRule
{
    public RuleResult Evaluate((string Host, string Path, string? Text) features)
    {
        // Detection logic here
        return new RuleResult(score, reasons, tags);
    }
}
```

### Training Models
```bash
cd src/PhishRadar.Training
dotnet run              # Train all models
dotnet run -- --test    # Quick test
dotnet run -- --eval    # Full evaluation
```

## Project Structure

```
src/
├── Api/                 # Web API
├── Core/                # Models and interfaces  
├── Rules/               # Detection rules and AI
├── Infrastructure/      # External services
├── PhishRadar.Training/ # ML training
└── WebExtension/        # Browser extension

scripts/                 # Training and demo scripts
```

## License

---

**Built for practical Vietnamese cybersecurity applications.** 🇻🇳