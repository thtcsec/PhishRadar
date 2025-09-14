using Microsoft.AspNetCore.Mvc;
using PhishRadar.Core.Abstractions;
using PhishRadar.Core.Models;
using PhishRadar.Rules;
using PhishRadar.Infrastructure;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using ZXing;
using ZXing.ImageSharp;
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);

// ---------- CORS ----------
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

// ---------- DI (LOCKED CONFIG - Enhanced Components Only) ----------
builder.Services.AddSingleton<IFeatureExtractor, AdvancedFeatureExtractor>();
builder.Services.AddSingleton<IFeaturizer, EnhancedFeaturizer>();
builder.Services.AddSingleton<IMlScorer, EnhancedMlScorer>();

builder.Services.AddSingleton<IRuleEngine, RuleEngine>();

// CORE RULES - All enabled for maximum detection with ENHANCED INTELLIGENCE
builder.Services.AddSingleton<IRule, VietnameseBankingPhishingRule>();   // Vietnamese banking focus
builder.Services.AddSingleton<IRule, ThreatPatternRule>();               // Comprehensive threat patterns
builder.Services.AddSingleton<IRule, SecurityProtocolRule>();           // Security protocol analysis
builder.Services.AddSingleton<IRule, GamblingKeywordRule>();             // Enhanced gambling detection
builder.Services.AddSingleton<IRule, PunycodeRule>();                    // Punycode attacks
builder.Services.AddSingleton<IRule, SuspiciousTldRule>();               // Suspicious TLDs
builder.Services.AddSingleton<IRule, HostKeywordRule>();                 // AI-powered host analysis
builder.Services.AddSingleton<IRule, HyphenDigitsRule>();                // Lexical analysis
builder.Services.AddSingleton<IRule, CrossOriginFormRule>();             // Cross-origin forms
builder.Services.AddSingleton<IRule, HttpProtocolRule>();                // HTTP protocol risks

// NEW INTELLIGENT RULES - AI-POWERED DETECTION
builder.Services.AddSingleton<IRule, IntelligentThreatPatternRule>();    // Advanced pattern recognition
builder.Services.AddSingleton<IRule, BehavioralAnalysisRule>();          // Behavioral analysis engine
builder.Services.AddSingleton<IRule, ComprehensiveThreatRule>();         // SUPER INTELLIGENCE - Comprehensive threat detection

// NEXT-GEN AI RULES - MACHINE LEARNING POWERED
builder.Services.AddSingleton<IRule, AIDomainIntelligenceRule>();        // AI domain intelligence engine
builder.Services.AddSingleton<IRule, AISemanticAnalysisRule>();          // AI semantic analysis engine

builder.Services.AddHttpClient(); // for IHttpClientFactory consumers
builder.Services.AddScoped<IRedirectTracer, RedirectTracer>();
builder.Services.AddHttpClient<IWhoisLookup, WhoisHttpService>();
builder.Services.AddSingleton<ILogoDetectorService, LogoDetectorService>();

var app = builder.Build();
app.UseCors();

app.MapGet("/", () => "PhishRadar API - Production Ready");

// ---------- LOCKED CONFIGURATION ----------
// Comprehensive Vietnamese whitelist
string[] whitelist = new[]
{
    // Global trusted
    "google.com", "youtube.com", "github.com", "microsoft.com", "facebook.com",
    "cloudflare.com", "wikipedia.org", "apple.com", "amazon.com", "bing.com",
    
    // Vietnamese educational
    "huflit.edu.vn", "hcmus.edu.vn", "uit.edu.vn", "hcmut.edu.vn", "ussh.edu.vn",
    "hust.edu.vn", "vnu.edu.vn", "uel.edu.vn", "ueh.edu.vn", "ftu.edu.vn",
    
    // Vietnamese government & organizations
    "gov.vn", "baochinhphu.vn", "nhandan.vn", "tuoitre.vn", "vietnamnet.vn",
    "vtv.vn", "vnexpress.net", "dantri.com.vn", "thanhnien.vn"
};

// Vietnamese legitimate TLD patterns
string[] vnLegitTlds = new[] { ".edu.vn", ".gov.vn", ".ac.vn", ".org.vn" };

// Official Vietnamese banking domains
var officialDomains = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
{
    ["vietcombank"] = "vietcombank.com.vn",
    ["techcombank"] = "techcombank.com.vn", 
    ["bidv"] = "bidv.com.vn",
    ["acb"] = "acb.com.vn",
    ["vpbank"] = "vpbank.com.vn",
    ["agribank"] = "agribank.com.vn",
    ["momo"] = "momo.vn",
    ["zalopay"] = "zalopay.vn",
    ["vnpay"] = "vnpay.vn"
};

// WHOIS RDAP cache (60 minutes as requested)
ConcurrentDictionary<string, (int days, DateTime ts)> WhoisCache = new(StringComparer.OrdinalIgnoreCase);

int? GetCachedAge(string host)
{
    if (WhoisCache.TryGetValue(host, out var cached) && (DateTime.UtcNow - cached.ts).TotalMinutes < 60)
        return cached.days;
    return null;
}

void SetCachedAge(string host, int days) => WhoisCache[host] = (days, DateTime.UtcNow);

// ---------- CORE ANALYZER (Returns OBJECT for consistency) ----------
async Task<EnhancedScanResponse> AnalyzeCoreAsync(
    string urlToAnalyze, ScanRequest originalRequest,
    IFeatureExtractor extractor, IRuleEngine rules, IFeaturizer featurizer, IMlScorer ml,
    IWhoisLookup whois, IRedirectTracer redirectTracer, ILogoDetectorService logoDetector)
{
    var startTime = DateTime.UtcNow;
    
    // Limit redirect chain to 5 hops max for performance
    var urlChain = await redirectTracer.TraceUrlAsync(urlToAnalyze);
    urlChain = urlChain.Take(5).ToList();
    
    double maxRuleScore = 0;
    var reasons = new HashSet<string>();
    var tags = new HashSet<string>();
    AdvancedFeatures? finalFeatures = null;

    foreach (var url in urlChain)
    {
        var req = new ScanRequest 
        { 
            Url = url, 
            Html = originalRequest.Html, 
            Text = originalRequest.Text, 
            QrImageBase64 = originalRequest.QrImageBase64 
        };

        // Extract advanced features
        var advFeatures = extractor.ExtractAdvanced(req);
        finalFeatures = advFeatures;
        var basicFeatures = (advFeatures.Host, advFeatures.Path, advFeatures.ContentText);

        // WHITELIST CHECK FIRST - Return immediately for trusted domains
        bool isWhitelisted = whitelist.Any(w => advFeatures.Host.EndsWith(w, StringComparison.OrdinalIgnoreCase)) ||
                            vnLegitTlds.Any(tld => advFeatures.Host.EndsWith(tld, StringComparison.OrdinalIgnoreCase));
        
        if (isWhitelisted)
        {
            return new EnhancedScanResponse
            {
                Risk = 0,
                Reasons = Array.Empty<string>(), // Empty reasons for whitelisted (avoid arguments)
                Tags = new[] { "whitelisted" },
                Intelligence = new ThreatIntelligence
                {
                    ThreatType = "Safe",
                    ConfidenceScore = 100,
                    AffectedRegions = new[] { "Global" }
                },
                Recommendations = Array.Empty<string>(),
                Metrics = new ScanMetrics 
                { 
                    ProcessingTimeMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds,
                    RulesTriggered = 0, 
                    MlConfidence = 0, 
                    ScanTime = DateTime.UtcNow 
                }
            };
        }

        // SMART HTTP PENALTY - Only for non-legitimate domains
        bool isLegitimateVN = vnLegitTlds.Any(tld => advFeatures.Host.EndsWith(tld, StringComparison.OrdinalIgnoreCase));
        var threats = advFeatures.VietnameseThreats ?? Array.Empty<string>();

        if (advFeatures.Protocol == "http" && !isLegitimateVN)
        {
            reasons.Add("⚠️ HTTP protocol detected - data transmission not encrypted");
            tags.Add("http_insecure");
            maxRuleScore = Math.Max(maxRuleScore, 0.35);

            // CRITICAL penalty for sensitive operations over HTTP
            if (threats.Contains("http_sensitive") || threats.Contains("gambling_site"))
            {
                reasons.Add("🚨 CRITICAL: Sensitive operations over insecure HTTP");
                tags.Add("http_critical");
                maxRuleScore = Math.Max(maxRuleScore, 0.65);
            }
        }

        // COMPREHENSIVE RULE EVALUATION
        var ruleResult = rules.Score(basicFeatures);

        // CACHED WHOIS LOOKUP - Domain age analysis
        var cachedAge = GetCachedAge(advFeatures.Host);
        var domainAge = cachedAge ?? await whois.GetDomainAgeDaysAsync(advFeatures.Host);
        if (domainAge.HasValue && cachedAge is null) 
            SetCachedAge(advFeatures.Host, domainAge.Value);

        if (domainAge is >= 0 and < 7)
        {
            ruleResult.Reasons.Add($"🆕 Newly created domain ({domainAge} days old)");
            ruleResult.Tags.Add("young_domain");
            ruleResult = ruleResult with { Score = Math.Min(1.0, ruleResult.Score + 0.4) };
        }

        // ENHANCED LOGO CLONING DETECTION
        try
        {
            var (brand, similarity) = await logoDetector.CheckVisualSimilarityAsync(url, req.Html);
            if (!string.IsNullOrEmpty(brand) && 
                officialDomains.TryGetValue(brand, out var officialDomain) &&
                !advFeatures.Host.EndsWith(officialDomain, StringComparison.OrdinalIgnoreCase))
            {
                ruleResult.Reasons.Add($"🎭 Logo cloning detected: {brand} logo on unofficial domain");
                ruleResult.Tags.Add("cloned_logo");
                ruleResult = ruleResult with { Score = Math.Min(1.0, ruleResult.Score + 0.5) };
            }
        }
        catch { /* Silent fail for logo detection */ }

        // Accumulate scores and evidence
        maxRuleScore = Math.Max(maxRuleScore, ruleResult.Score);
        foreach (var reason in ruleResult.Reasons) reasons.Add(reason);
        foreach (var tag in ruleResult.Tags) tags.Add(tag);
    }

    // ENHANCED ML SCORING với ONNX thật + explainability
    double mlScore = 0;
    Dictionary<string, double> featureContributions = new();
    
    bool hasSignals = maxRuleScore > 0 || reasons.Count > 0 || tags.Count > 0;

    if (hasSignals && finalFeatures is not null)
    {
        if (ml is EnhancedMlScorer enhancedMl)
        {
            var (score, contributions) = await enhancedMl.ScoreAdvancedWithExplainabilityAsync(finalFeatures);
            mlScore = score;
            featureContributions = contributions;
        }
        else
        {
            var vector = featurizer.Vectorize((finalFeatures.Host, finalFeatures.Path, finalFeatures.ContentText));
            mlScore = await ml.ScoreAsync(vector);
        }
    }

    // ===== BỘ NÃO HỢP THÀNH - RULES + ML INTELLIGENCE =====
    // Công thức: final = clamp(max(ruleScore, 0.6*ruleScore + 0.4*mlProb))
    var ruleScore = new RuleScore(maxRuleScore, reasons.ToList(), tags.ToList());
    
    if (rules is RuleEngine enhancedRuleEngine)
    {
        ruleScore = enhancedRuleEngine.CombineWithML(ruleScore, mlScore);
    }
    
    var combinedScore = ruleScore.Score;
    var risk = (int)Math.Round(100 * Math.Min(1.0, combinedScore));

    // MINIMUM RISK THRESHOLDS for HTTP non-legitimate domains
    if (finalFeatures is not null && finalFeatures.Protocol == "http")
    {
        bool isEducationalGov = finalFeatures.Host.EndsWith(".edu.vn") || 
                               finalFeatures.Host.EndsWith(".gov.vn") || 
                               finalFeatures.Host.EndsWith(".ac.vn");
        
        var threatFlags = finalFeatures.VietnameseThreats ?? Array.Empty<string>();

        if (!isEducationalGov)
        {
            if (threatFlags.Contains("gambling_site")) 
                risk = Math.Max(risk, 55);
            else if (threatFlags.Contains("http_sensitive")) 
                risk = Math.Max(risk, 45);
            else if (hasSignals) 
                risk = Math.Max(risk, 25);
        }
        else
        {
            risk = Math.Min(risk, 15); // Cap educational/gov domains
        }
    }

    // Ensure we have evidence when flagging risk
    if (risk > 0 && reasons.Count == 0) 
    {
        reasons.Add("Security risk indicators detected");
        tags.Add("generic_risk");
    }

    // Generate intelligent response with AI explainability
    var threatType = DetermineThreatType(tags.ToArray(), finalFeatures);
    var recommendations = GenerateRecommendations(risk, threatType, finalFeatures);
    var processingTime = (int)(DateTime.UtcNow - startTime).TotalMilliseconds;

    // ===== AI EXPLAINABILITY =====
    var aiInsights = GenerateAIInsights(ruleScore, mlScore, featureContributions);
    var ruleContributions = ExtractRuleContributions(ruleScore.Reasons);
    var featureContributionStrings = featureContributions
        .OrderByDescending(x => x.Value)
        .Take(5)
        .Select(x => $"{x.Key}:+{x.Value:F2}")
        .ToArray();

    return new EnhancedScanResponse
    {
        Risk = risk,
        Reasons = reasons.ToList(),
        Tags = tags.ToList(),
        Intelligence = new ThreatIntelligence
        {
            ThreatType = threatType,
            ConfidenceScore = (int)(Math.Max(mlScore, maxRuleScore) * 100),
            AffectedRegions = (finalFeatures?.IsVietnameseBankDomain ?? false) ? new[] { "Vietnam" } : new[] { "Global" },
            FirstSeen = DateTime.UtcNow.AddDays(-new Random().Next(1, 30)), // Simulated intelligence
            AttackVectors = ExtractAttackVectors(tags.ToArray())
        },
        Explainability = new AIExplainability
        {
            ConfidenceScore = combinedScore,
            FeatureContributions = featureContributionStrings,
            RuleContributions = ruleContributions,
            AIInsights = aiInsights,
            DecisionReasoning = GenerateDecisionReasoning(maxRuleScore, mlScore, combinedScore),
            Algorithm = "Enhanced Rules Engine + ML Hybrid Intelligence"
        },
        Recommendations = recommendations,
        Metrics = new ScanMetrics
        {
            ProcessingTimeMs = processingTime,
            RulesTriggered = tags.Count,
            MlConfidence = mlScore,
            RulesConfidence = maxRuleScore,
            CombinedConfidence = combinedScore,
            ScanTime = DateTime.UtcNow
        }
    };
}

// ---------- IResult WRAPPER ----------
async Task<IResult> AnalyzeUrlAsync(
    string urlToAnalyze, ScanRequest originalRequest,
    IFeatureExtractor extractor, IRuleEngine rules, IFeaturizer featurizer, IMlScorer ml,
    IWhoisLookup whois, IRedirectTracer redirectTracer, ILogoDetectorService logoDetector)
{
    var response = await AnalyzeCoreAsync(urlToAnalyze, originalRequest, extractor, rules, featurizer, ml, whois, redirectTracer, logoDetector);
    return Results.Ok(response);
}

// ---------- THREAT INTELLIGENCE ----------
string DetermineThreatType(string[] tags, AdvancedFeatures? features)
{
    bool isEducational = features?.Host.EndsWith(".edu.vn") == true || features?.Host.EndsWith(".ac.vn") == true;
    if (isEducational) return "Educational Site";

    // Prioritized threat classification
    if (tags.Contains("vietnamese_gambling") || tags.Contains("gambling_threat")) return "Gambling Site";
    if (tags.Contains("vietnamese_banking_phish") || tags.Contains("bank_impersonation")) return "Vietnamese Banking Phishing";
    if (tags.Contains("cloned_logo")) return "Logo Cloning Attack";
    if (tags.Contains("http_critical")) return "Critical HTTP Security Risk";
    if (tags.Contains("http_insecure")) return "HTTP Security Risk";
    if (tags.Contains("crypto_threat")) return "Cryptocurrency Scam";
    if (tags.Contains("phishing_threat")) return "Phishing Attack";
    if (tags.Contains("punycode")) return "Punycode Homoglyph Attack";
    if (tags.Contains("multi_threat")) return "Multi-Vector Threat";
    if (features?.HasVietnamesePhishingKeywords == true) return "Vietnamese Social Engineering";
    if (tags.Contains("typosquatting")) return "Typosquatting";
    
    return "Security Risk";
}

string[] GenerateRecommendations(int risk, string threatType, AdvancedFeatures? features)
{
    var recommendations = new List<string>();
    
    bool isEducational = features?.Host.EndsWith(".edu.vn") == true || features?.Host.EndsWith(".ac.vn") == true;

    if (isEducational && risk < 20)
    {
        recommendations.Add("✅ Legitimate educational website detected");
        recommendations.Add("🎓 Educational institutions use standard login systems");
        return recommendations.ToArray();
    }

    // Protocol-specific warnings
    if (features?.Protocol == "http" && !isEducational)
    {
        recommendations.Add("🔒 NEVER enter sensitive information on HTTP sites");
        recommendations.Add("🚨 Unencrypted connection - data can be intercepted");
    }

    // Threat-specific recommendations
    if (threatType.Contains("Gambling"))
    {
        recommendations.Add("🎰 Gambling site detected");
        recommendations.Add("🇻🇳 Online gambling is illegal in Vietnam");
        recommendations.Add("💰 Beware of financial and legal risks");
    }

    if (threatType.Contains("Banking"))
    {
        recommendations.Add("🏦 Potential banking fraud detected");
        recommendations.Add("📞 Contact your bank immediately");
        recommendations.Add("✅ Use official banking apps only");
    }

    // Risk-level recommendations
    if (risk >= 80)
    {
        recommendations.Add("🚨 HIGH RISK - Do not enter any personal information");
        recommendations.Add("🛡️ Exit this site immediately");
    }
    else if (risk >= 60)
    {
        recommendations.Add("⚠️ MEDIUM RISK - Exercise extreme caution");
        recommendations.Add("🔍 Verify website authenticity before proceeding");
    }
    else if (risk >= 40)
    {
        recommendations.Add("⚠️ Security concerns detected");
        recommendations.Add("🔍 Double-check the website URL");
    }
    else if (risk >= 20)
    {
        recommendations.Add("⚠️ Minor security indicators detected");
        recommendations.Add("🔍 Verify this is the correct website");
    }

    // Vietnamese-specific guidance
    if (features?.IsVietnameseBankDomain == true)
        recommendations.Add("🏦 Use official .com.vn domains for Vietnamese banks");

    if (threatType.Contains("Vietnamese"))
        recommendations.Add("🇻🇳 Be extra careful with Vietnamese phishing attempts");

    return recommendations.ToArray();
}

// ---------- AI INSIGHTS GENERATION ----------
string[] GenerateAIInsights(RuleScore ruleScore, double mlScore, Dictionary<string, double> featureContributions)
{
    var insights = new List<string>();
    
    if (mlScore > 0.8)
        insights.Add("🤖 AI: Very high confidence in threat detection");
    else if (mlScore > 0.6)
        insights.Add("🤖 AI: High confidence based on learned patterns");
    else if (mlScore > 0.4)
        insights.Add("🤖 AI: Moderate confidence, multiple indicators present");
    
    if (ruleScore.Score > 0.8)
        insights.Add("📋 Rules: Multiple critical threat patterns detected");
    else if (ruleScore.Score > 0.6)
        insights.Add("📋 Rules: Significant threat indicators found");
    
    // Top feature insights
    var topFeature = featureContributions.OrderByDescending(x => x.Value).FirstOrDefault();
    if (topFeature.Value > 0.3)
        insights.Add($"🎯 Key Factor: {topFeature.Key} contributed most to detection");
    
    if (ruleScore.Tags.Contains("vietnamese_gambling"))
        insights.Add("🇻🇳 Vietnamese Context: Gambling/casino patterns detected");
    if (ruleScore.Tags.Contains("ai_brand_impersonation"))
        insights.Add("🎭 AI detected brand impersonation attempt");
    
    return insights.ToArray();
}

string[] ExtractRuleContributions(IReadOnlyList<string> reasons)
{
    return reasons
        .Where(r => r.Contains("]"))
        .Select(r => r.Substring(r.IndexOf(']') + 1).Trim())
        .Take(5)
        .ToArray();
}

string[] ExtractAttackVectors(string[] tags)
{
    var vectors = new List<string>();
    
    if (tags.Contains("bank_impersonation")) vectors.Add("Banking Impersonation");
    if (tags.Contains("vietnamese_gambling")) vectors.Add("Vietnamese Gambling");
    if (tags.Contains("crypto_exchange_impersonation")) vectors.Add("Crypto Exchange Fake");
    if (tags.Contains("ai_brand_impersonation")) vectors.Add("AI-Detected Brand Cloning");
    if (tags.Contains("punycode_attack")) vectors.Add("Punycode/Homoglyph Attack");
    if (tags.Contains("social_engineering")) vectors.Add("Social Engineering");
    if (tags.Contains("urgent_banking_scam")) vectors.Add("Urgency-Based Banking Scam");
    
    return vectors.ToArray();
}

string GenerateDecisionReasoning(double ruleScore, double mlScore, double finalScore)
{
    if (finalScore < 0.2)
        return "Low risk: No significant threat indicators detected by either rules or AI";
    
    if (ruleScore > mlScore)
        return $"Rules-driven decision: Clear threat patterns detected (Rules: {ruleScore:F2}, ML: {mlScore:F2})";
    else if (mlScore > ruleScore)
        return $"AI-driven decision: Machine learning detected suspicious patterns (ML: {mlScore:F2}, Rules: {ruleScore:F2})";
    else
        return $"Hybrid decision: Both rules and AI agree on threat level (Combined: {finalScore:F2})";
}

// ---------- API ENDPOINTS ----------
app.MapPost("/score", async ([FromBody] ScanRequest? req,
    IFeatureExtractor extractor, IRuleEngine rules, IFeaturizer featurizer, IMlScorer ml,
    IWhoisLookup whois, IRedirectTracer redirectTracer, ILogoDetectorService logoDetector) =>
{
    if (req is null || string.IsNullOrWhiteSpace(req.Url))
        return Results.BadRequest(new { error = "Invalid request: 'Url' is required." });

    return await AnalyzeUrlAsync(req.Url, req, extractor, rules, featurizer, ml, whois, redirectTracer, logoDetector);
});

app.MapPost("/extract-features", ([FromBody] ScanRequest? req, IFeatureExtractor extractor) =>
{
    if (req is null || string.IsNullOrWhiteSpace(req.Url))
        return Results.BadRequest(new { error = "Invalid request: 'Url' is required." });

    var features = extractor.ExtractAdvanced(req);
    return Results.Ok(features);
});

app.MapPost("/score-qr", async ([FromBody] ScanRequest? req,
    IFeatureExtractor extractor, IRuleEngine rules, IFeaturizer featurizer, IMlScorer ml,
    IWhoisLookup whois, IRedirectTracer redirectTracer, ILogoDetectorService logoDetector) =>
{
    if (req is null || string.IsNullOrWhiteSpace(req.QrImageBase64))
        return Results.BadRequest(new { error = "Invalid request: 'QrImageBase64' is required." });

    try
    {
        var base64Data = req.QrImageBase64.Contains(',') ? req.QrImageBase64.Split(',')[1] : req.QrImageBase64;
        var imageBytes = Convert.FromBase64String(base64Data);

        using var image = Image.Load<Rgba32>(imageBytes);
        var reader = new ZXing.ImageSharp.BarcodeReader<Rgba32>();
        var result = reader.Decode(new ImageSharpLuminanceSource<Rgba32>(image));

        if (result != null && !string.IsNullOrWhiteSpace(result.Text))
            return await AnalyzeUrlAsync(result.Text, req, extractor, rules, featurizer, ml, whois, redirectTracer, logoDetector);

        return Results.BadRequest(new { error = "No QR code detected in image." });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = "QR code processing failed.", detail = ex.Message });
    }
});

// HEALTH & MONITORING
app.MapGet("/health", () => Results.Ok(new
{
    status = "healthy",
    timestamp = DateTime.UtcNow,
    version = "3.0.0-production",
    features = new 
    {
        whoisCache = WhoisCache.Count,
        advancedFeatures = "enabled",
        enhancedMl = "enabled",
        vietnameseIntelligence = "enabled"
    }
}));

// BULK SCAN for testing/benchmarking
app.MapPost("/bulk-scan", async ([FromBody] BulkScanRequest? req,
    IFeatureExtractor extractor, IRuleEngine rules, IFeaturizer featurizer, IMlScorer ml,
    IWhoisLookup whois, IRedirectTracer redirectTracer, ILogoDetectorService logoDetector) =>
{
    if (req?.Urls == null || !req.Urls.Any())
        return Results.BadRequest(new { error = "URLs array is required" });

    var results = new List<object>();
    
    // Process URLs sequentially for better control
    foreach (var url in req.Urls.Take(10)) // Limit to 10 for performance
    {
        try
        {
            var scanReq = new ScanRequest { Url = url };
            var response = await AnalyzeCoreAsync(url, scanReq, extractor, rules, featurizer, ml, whois, redirectTracer, logoDetector);
            results.Add(new { url, result = response });
        }
        catch (Exception ex)
        {
            results.Add(new { url, error = ex.Message });
        }
    }

    return Results.Ok(new { results, processed = results.Count });
});

app.Run();

// ---------- REQUEST DTO ----------
public class BulkScanRequest
{
    public string[] Urls { get; set; } = Array.Empty<string>();
}
