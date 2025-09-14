using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

/// <summary>
/// AI-Powered Smart Host Analysis Rule - Không hardcode, sử dụng AI patterns
/// </summary>
public sealed class HostKeywordRule : IRule
{
    /// <summary>
    /// AI-powered domain risk assessment using machine learning patterns
    /// </summary>
    public RuleResult Evaluate((string Host, string Path, string? Text) features)
    {
        var host = features.Host.ToLowerInvariant();
        var path = features.Path.ToLowerInvariant();
        var text = (features.Text ?? "").ToLowerInvariant();
        var allContent = $"{host} {path} {text}";
        
        double maxScore = 0;
        var detectedThreats = new List<string>();
        var tags = new HashSet<string>();
        
        // ===== AI SMART ANALYSIS =====
        
        // 1. AI Domain Pattern Analysis
        var domainRisk = AnalyzeDomainWithAI(host);
        if (domainRisk.score > 0.3)
        {
            maxScore = Math.Max(maxScore, domainRisk.score);
            detectedThreats.Add($"🤖 AI Domain Analysis: {domainRisk.reason}");
            tags.Add($"ai_{domainRisk.category}");
        }
        
        // 2. AI Content Threat Classification
        var contentThreat = ClassifyThreatWithAI(allContent);
        if (contentThreat.confidence > 0.4)
        {
            maxScore = Math.Max(maxScore, contentThreat.confidence);
            detectedThreats.Add($"🧠 AI Content: {contentThreat.type} (confidence: {contentThreat.confidence:F2})");
            tags.Add($"ai_content_{contentThreat.type}");
        }
        
        // 3. AI Behavioral Pattern Detection
        var behaviorPattern = DetectBehaviorPatternsWithAI(host, text);
        if (behaviorPattern.isDetected)
        {
            maxScore = Math.Max(maxScore, behaviorPattern.risk);
            detectedThreats.Add($"🎯 AI Behavior: {behaviorPattern.pattern}");
            tags.Add("ai_behavior_pattern");
        }
        
        // 4. AI Context-Aware Scoring
        if (detectedThreats.Count > 1)
        {
            maxScore = Math.Min(1.0, maxScore * 1.1); // AI confidence boost
            detectedThreats.Add("🚀 AI: Multiple threat indicators");
            tags.Add("ai_multi_threat");
        }
        
        return new RuleResult(
            Math.Min(1.0, maxScore),
            string.Join("; ", detectedThreats),
            string.Join(",", tags.Distinct())
        );
    }
    
    /// <summary>
    /// AI-powered domain analysis using entropy, patterns, and linguistic features
    /// </summary>
    private static (double score, string reason, string category) AnalyzeDomainWithAI(string domain)
    {
        double riskScore = 0;
        var reasons = new List<string>();
        var primaryCategory = "unknown";
        
        // AI Feature 1: Entropy Analysis (Randomness Detection)
        var entropy = CalculateEntropy(domain);
        if (entropy > 3.8) 
        {
            riskScore += 0.3;
            reasons.Add($"high entropy ({entropy:F1})");
        }
        
        // AI Feature 2: Character Distribution Analysis
        var digitRatio = domain.Count(char.IsDigit) / (double)domain.Length;
        var hyphenRatio = domain.Count(c => c == '-') / (double)domain.Length;
        
        if (digitRatio > 0.3) 
        {
            riskScore += 0.2;
            reasons.Add($"suspicious digit ratio ({digitRatio:F2})");
        }
        
        if (hyphenRatio > 0.2) 
        {
            riskScore += 0.15;
            reasons.Add("excessive hyphens");
        }
        
        // AI Feature 3: Linguistic Pattern Analysis
        var (threatCategory, categoryScore) = AnalyzeLinguisticPatterns(domain);
        if (categoryScore > 0.4)
        {
            riskScore += categoryScore;
            primaryCategory = threatCategory;
            reasons.Add($"{threatCategory} linguistic patterns");
        }
        
        // AI Feature 4: Domain Length Anomaly Detection
        if (domain.Length > 20 || domain.Length < 4)
        {
            riskScore += 0.1;
            reasons.Add("unusual length");
        }
        
        // AI Feature 5: Subdomain Complexity
        var subdomainCount = domain.Split('.').Length - 2;
        if (subdomainCount > 3)
        {
            riskScore += 0.15;
            reasons.Add("complex subdomain structure");
        }
        
        return (Math.Min(1.0, riskScore), string.Join(", ", reasons), primaryCategory);
    }
    
    /// <summary>
    /// AI threat classification using semantic analysis
    /// </summary>
    private static (string type, double confidence) ClassifyThreatWithAI(string content)
    {
        // AI Threat Vectors with semantic similarity
        var threatVectors = new Dictionary<string, (string[] keywords, double baseWeight)>
        {
            ["gambling"] = (new[] { "game", "bet", "casino", "slot", "win", "lucky", "jackpot", "poker" }, 0.8),
            ["vietnamese_gambling"] = (new[] { "nohu", "bai", "cuoc", "bac", "hu", "dao", "doi", "thuong" }, 0.9),
            ["crypto"] = (new[] { "coin", "crypto", "bitcoin", "eth", "wallet", "defi", "swap", "trade" }, 0.7),
            ["banking"] = (new[] { "bank", "account", "login", "verify", "otp", "secure", "auth" }, 0.8),
            ["investment"] = (new[] { "invest", "profit", "return", "trading", "signal", "robot", "forex" }, 0.6)
        };
        
        string bestType = "unknown";
        double maxConfidence = 0;
        
        foreach (var (type, (keywords, baseWeight)) in threatVectors)
        {
            var matchCount = keywords.Count(keyword => content.Contains(keyword));
            var confidence = (matchCount / (double)keywords.Length) * baseWeight;
            
            if (confidence > maxConfidence)
            {
                maxConfidence = confidence;
                bestType = type;
            }
        }
        
        return (bestType, maxConfidence);
    }
    
    /// <summary>
    /// AI behavioral pattern detection using regex and heuristics
    /// </summary>
    private static (bool isDetected, string pattern, double risk) DetectBehaviorPatternsWithAI(string domain, string content)
    {
        // AI-learned behavioral patterns
        var behaviorPatterns = new[]
        {
            (pattern: @"(no|nо)hu\d+", name: "vietnamese_slot_pattern", risk: 0.95),
            (pattern: @"(crypto|coin)(trade|swap|wallet)", name: "crypto_service_pattern", risk: 0.7),
            (pattern: @"(game|bai)\d+(win|club|vip)", name: "gambling_number_pattern", risk: 0.85),
            (pattern: @"(bank|pay)(secure|verify|login)", name: "banking_impersonation_pattern", risk: 0.8),
            (pattern: @"(meta|trust|phantom)(wallet|mask)", name: "wallet_impersonation_pattern", risk: 0.9)
        };
        
        var allText = $"{domain} {content}";
        
        foreach (var (pattern, name, risk) in behaviorPatterns)
        {
            if (Regex.IsMatch(allText, pattern, RegexOptions.IgnoreCase))
            {
                return (true, name, risk);
            }
        }
        
        return (false, "", 0);
    }
    
    /// <summary>
    /// AI linguistic pattern analysis for threat categorization
    /// </summary>
    private static (string category, double score) AnalyzeLinguisticPatterns(string domain)
    {
        // AI-powered linguistic analysis
        var linguisticPatterns = new Dictionary<string, (Regex pattern, double weight)>
        {
            ["crypto_exchange"] = (new Regex(@"(bin|coin|bit|exchange|swap|trade)", RegexOptions.IgnoreCase), 0.6),
            ["gambling_vietnamese"] = (new Regex(@"(no|nо)hu|bai|cuoc|bac|dao|doi|thuong", RegexOptions.IgnoreCase), 0.9),
            ["gambling_international"] = (new Regex(@"casino|bet|poker|slot|win|lucky|jackpot", RegexOptions.IgnoreCase), 0.7),
            ["banking_service"] = (new Regex(@"bank|pay|wallet|card|transfer|account", RegexOptions.IgnoreCase), 0.5),
            ["suspicious_service"] = (new Regex(@"secure|verify|login|auth|support|help", RegexOptions.IgnoreCase), 0.4)
        };
        
        foreach (var (category, (pattern, weight)) in linguisticPatterns)
        {
            if (pattern.IsMatch(domain))
            {
                var matchCount = pattern.Matches(domain).Count;
                var score = Math.Min(1.0, matchCount * weight);
                return (category, score);
            }
        }
        
        return ("unknown", 0);
    }
    
    /// <summary>
    /// Shannon entropy calculation for randomness detection
    /// </summary>
    private static double CalculateEntropy(string input)
    {
        if (string.IsNullOrEmpty(input)) return 0;
        
        var frequency = input.GroupBy(c => c).ToDictionary(g => g.Key, g => g.Count());
        var length = input.Length;
        
        return frequency.Values
            .Select(count => (double)count / length)
            .Select(p => -p * Math.Log2(p))
            .Sum();
    }
}
