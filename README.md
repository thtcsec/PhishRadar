# PhishRadar

A URL and QR code security scanner built for detecting Vietnamese phishing attacks. Uses rule-based detection combined with machine learning to identify malicious websites.

## What it does

- Scans URLs for phishing indicators
- Analyzes QR codes for embedded malicious links
- Detects Vietnamese banking and gambling scams
- Checks for domain impersonation and logo cloning
- Provides risk scoring from 0-100

## Core Features

### Multi-layer Detection
- **Rule Engine**: 15+ detection rules for common attack patterns
- **ML Scoring**: Machine learning model for pattern recognition  
- **Domain Analysis**: WHOIS lookups, age verification, entropy analysis
- **Logo Detection**: Computer vision for brand impersonation
- **Redirect Tracing**: Follows URL chains to final destination

### Vietnamese Focus
- Banking phishing (Vietcombank, Techcombank, etc.)
- Gambling sites (illegal in Vietnam)
- Government portal spoofing (.gov.vn verification)
- Crypto exchange fakes
- Vietnamese-specific social engineering patterns

### QR Code Security
- Extracts URLs from QR code images
- Analyzes embedded links for threats
- Base64 image processing support

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

### Scan QR Code
```bash
POST /score-qr
Content-Type: application/json

{
  "qrImageBase64": "data:image/png;base64,..."
}
```

### Response Format
```json
{
  "risk": 75,
  "riskLevel": "HIGH",
  "reasons": [
    "Vietnamese bank name detected with suspicious domain",
    "Domain created 3 days ago",
    "HTTP protocol on sensitive site"
  ],
  "tags": ["vietnamese_banking", "young_domain", "http_insecure"],
  "intelligence": {
    "threatType": "Vietnamese Banking Phishing",
    "confidenceScore": 85,
    "affectedRegions": ["Vietnam"]
  },
  "recommendations": [
    "Do not enter personal information",
    "Verify with official bank website",
    "Use official mobile banking app"
  ]
}
```

## Technical Stack

- **.NET 8** - Core framework
- **ASP.NET Core** - Web API
- **ML.NET / ONNX** - Machine learning models
- **ImageSharp** - Image processing
- **ZXing** - QR code reading

## Project Structure

```
src/
├── Api/           # Web API endpoints
├── Core/          # Domain models and interfaces  
├── Rules/         # Detection rules and ML scoring
├── Infrastructure/ # External services (WHOIS, redirects)
└── Training/      # ML model training (if applicable)
```

## Running Locally

```bash
# Clone and build
git clone <repo>
cd phishradar
dotnet build

# Run API
cd src/Api  
dotnet run
```

API will be available at `http://localhost:5122`

## Key Detection Rules

1. **Vietnamese Banking Rule** - Detects fake banking sites
2. **Gambling Keyword Rule** - Identifies illegal gambling sites
3. **Punycode Rule** - Catches internationalized domain attacks
4. **Host Keyword Rule** - AI-powered domain analysis
5. **Behavioral Analysis** - Pattern-based threat detection
6. **Logo Cloning Detection** - Visual similarity analysis

## Performance

- Response time: ~150ms average
- Processes redirect chains up to 5 hops
- WHOIS caching (60 minutes)
- Handles both URL and QR code inputs

## Whitelisting

Pre-configured whitelist for legitimate Vietnamese domains:
- Educational (.edu.vn, .ac.vn)
- Government (.gov.vn)
- Major Vietnamese websites
- International tech companies

## Development

The system is designed to be extended with new rules. Each rule implements `IRule` interface:

```csharp
public interface IRule
{
    RuleResult Evaluate((string Host, string Path, string? Text) features);
}
```

Rules are combined using a weighted scoring system and enhanced with ML predictions.

## License


---

Built for practical.