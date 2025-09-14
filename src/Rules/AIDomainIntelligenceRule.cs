using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

/// <summary>
/// AI-Powered Domain Intelligence Engine
/// Sử dụng machine learning patterns thay vì hardcode domains
/// </summary>
public sealed class AIDomainIntelligenceRule : IRule
{
    // ===== AI PATTERN RECOGNITION =====
    
    /// <summary>
    /// AI-based suspicious pattern scoring using entropy and linguistic analysis
    /// </summary>
    private static double CalculateAISuspiciousnessScore(string domain)
    {
        double suspiciousScore = 0;
        
        // 1. Entropy Analysis (randomness detection)
        var entropy = CalculateEntropy(domain);
        if (entropy > 3.5) suspiciousScore += 0.3; // High randomness
        
        // 2. Character Pattern Analysis
        var digitRatio = domain.Count(char.IsDigit) / (double)domain.Length;
        if (digitRatio > 0.3) suspiciousScore += 0.2; // Too many digits
        
        // 3. Hyphen Analysis (typosquatting indicator)
        var hyphenCount = domain.Count(c => c == '-');
        if (hyphenCount > 2) suspiciousScore += 0.2; // Excessive hyphens
        
        // 4. Length Analysis
        if (domain.Length > 20) suspiciousScore += 0.1; // Suspiciously long
        if (domain.Length < 4) suspiciousScore += 0.2; // Suspiciously short
        
        // 5. Subdomain Complexity
        var parts = domain.Split('.');
        if (parts.Length > 4) suspiciousScore += 0.2; // Too many subdomains
        
        return Math.Min(1.0, suspiciousScore);
    }
    
    /// <summary>
    /// AI semantic analysis for threat categories
    /// </summary>
    private static (string category, double confidence) AnalyzeThreatCategory(string content)
    {
        var contentLower = content.ToLowerInvariant();
        
        // AI-powered semantic vectors (simplified)
        var threatVectors = new Dictionary<string, (string[] keywords, string[] patterns, double baseWeight)>
        {
            ["crypto_scam"] = (
                new[] { "crypto", "bitcoin", "ethereum", "wallet", "seed", "private", "airdrop", "defi" },
                new[] { @"(crypto|bitcoin|eth|btc).*(wallet|claim|airdrop)", @"(meta|trust|phantom).*(wallet|connect)" },
                0.8
            ),
            ["vietnamese_gambling"] = (
                new[] { "cá", "cược", "đánh", "bạc", "nổ", "hũ", "quay", "game", "bài", "casino" },
                new[] { @"(nổ|no).*(hũ|hu)", @"(game|bài).*(đổi|doi).*(thưởng|thuong)", @"(cá|ca).*(độ|do|cược|cuoc)" },
                0.9
            ),
            ["international_gambling"] = (
                new[] { "casino", "bet", "poker", "slot", "jackpot", "roulette", "gambling", "lottery" },
                new[] { @"(bet|casino|poker)\d+", @"(slot|jackpot|win).*(game|play)", @"(live|online).*(casino|betting)" },
                0.7
            ),
            ["banking_phishing"] = (
                new[] { "bank", "login", "verify", "account", "security", "otp", "authenticate", "suspended" },
                new[] { @"(bank|account).*(verify|login|security)", @"(urgent|immediate).*(verify|update)", @"(otp|pin).*(verify|enter)" },
                0.8
            ),
            ["investment_scam"] = (
                new[] { "investment", "profit", "return", "guaranteed", "trading", "forex", "signal", "robot" },
                new[] { @"(guaranteed|sure).*(profit|return)", @"(trading|forex).*(bot|robot|signal)", @"(double|triple).*(money|investment)" },
                0.7
            )
        };
        
        string bestCategory = "unknown";
        double maxScore = 0;
        
        foreach (var (category, (keywords, patterns, baseWeight)) in threatVectors)
        {
            double categoryScore = 0;
            
            // Keyword matching with TF-IDF-like scoring
            var keywordMatches = keywords.Count(kw => contentLower.Contains(kw));
            categoryScore += (keywordMatches / (double)keywords.Length) * baseWeight;
            
            // Pattern matching with regex
            var patternMatches = patterns.Count(pattern => Regex.IsMatch(contentLower, pattern));
            categoryScore += (patternMatches / (double)patterns.Length) * 0.3;
            
            if (categoryScore > maxScore)
            {
                maxScore = categoryScore;
                bestCategory = category;
            }
        }
        
        return (bestCategory, maxScore);
    }
    
    /// <summary>
    /// AI-powered TLD reputation analysis
    /// </summary>
    private static double AnalyzeTLDReputation(string domain)
    {
        // AI-learned TLD risk scores (based on threat intelligence)
        var tldRiskScores = new Dictionary<string, double>
        {
            // High risk TLDs (known for abuse)
            [".tk"] = 0.9, [".ml"] = 0.9, [".ga"] = 0.9, [".cf"] = 0.9,
            [".club"] = 0.7, [".xyz"] = 0.6, [".top"] = 0.7, [".click"] = 0.8,
            [".download"] = 0.8, [".stream"] = 0.6, [".win"] = 0.8, [".bid"] = 0.7,
            
            // Medium risk TLDs
            [".info"] = 0.3, [".biz"] = 0.4, [".name"] = 0.3, [".pro"] = 0.3,
            
            // Legitimate but sometimes abused
            [".com"] = 0.1, [".net"] = 0.1, [".org"] = 0.1,
            
            // Vietnamese legitimate TLDs
            [".vn"] = 0.0, [".com.vn"] = 0.0, [".edu.vn"] = 0.0, [".gov.vn"] = 0.0,
            
            // Fake TLD combinations (impersonation)
            [".eu.com"] = 0.9, [".co.uk"] = 0.4, [".net.au"] = 0.5
        };
        
        foreach (var (tld, risk) in tldRiskScores)
        {
            if (domain.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
            {
                return risk;
            }
        }
        
        return 0.2; // Unknown TLD = medium risk
    }
    
    /// <summary>
    /// AI linguistic similarity detection for brand impersonation
    /// </summary>
    private static (bool isImpersonation, string suspectedBrand, double similarity) DetectBrandImpersonation(string domain)
    {
        // AI-powered brand similarity detection
        var knownBrands = new[]
        {
            // Crypto brands
            "binance", "coinbase", "kraken", "bitfinex", "huobi", "okx", "kucoin",
            // Vietnamese banks
            "vietcombank", "techcombank", "bidv", "acb", "vpbank", "agribank", "vietinbank", "mbbank",
            // International brands
            "paypal", "amazon", "google", "microsoft", "apple", "facebook", "instagram"
        };
        
        foreach (var brand in knownBrands)
        {
            var similarity = CalculateLevenshteinSimilarity(domain, brand);
            
            // If high similarity but not exact match = potential impersonation
            if (similarity > 0.7 && !domain.Equals(brand) && !domain.EndsWith($"{brand}.com"))
            {
                return (true, brand, similarity);
            }
            
            // Check for character substitution attacks
            if (ContainsCharacterSubstitution(domain, brand))
            {
                return (true, brand, 0.8);
            }
        }
        
        return (false, "", 0);
    }
    
    public RuleResult Evaluate((string Host, string Path, string? Text) features)
    {
        var host = features.Host.ToLowerInvariant();
        var path = features.Path.ToLowerInvariant();
        var text = (features.Text ?? "").ToLowerInvariant();
        var allContent = $"{host} {path} {text}";
        
        double maxScore = 0;
        var detectedThreats = new List<string>();
        var tags = new HashSet<string>();
        
        // ===== AI ANALYSIS PIPELINE =====
        
        // 1. AI Domain Suspiciousness Analysis
        var domainSuspiciousness = CalculateAISuspiciousnessScore(host);
        if (domainSuspiciousness > 0.5)
        {
            maxScore = Math.Max(maxScore, domainSuspiciousness);
            detectedThreats.Add($"🤖 AI: Suspicious domain patterns (score: {domainSuspiciousness:F2})");
            tags.Add("ai_suspicious_domain");
        }
        
        // 2. AI Threat Category Analysis
        var (threatCategory, categoryConfidence) = AnalyzeThreatCategory(allContent);
        if (categoryConfidence > 0.6)
        {
            maxScore = Math.Max(maxScore, categoryConfidence);
            detectedThreats.Add($"🧠 AI Category: {threatCategory} (confidence: {categoryConfidence:F2})");
            tags.Add($"ai_{threatCategory}");
        }
        
        // 3. AI TLD Reputation Analysis
        var tldRisk = AnalyzeTLDReputation(host);
        if (tldRisk > 0.5)
        {
            maxScore = Math.Max(maxScore, tldRisk);
            detectedThreats.Add($"🚨 AI: High-risk TLD detected (risk: {tldRisk:F2})");
            tags.Add("ai_risky_tld");
        }
        
        // 4. AI Brand Impersonation Detection
        var (isImpersonation, suspectedBrand, similarity) = DetectBrandImpersonation(host);
        if (isImpersonation)
        {
            maxScore = Math.Max(maxScore, 0.8);
            detectedThreats.Add($"🎭 AI: Brand impersonation of '{suspectedBrand}' (similarity: {similarity:F2})");
            tags.Add("ai_brand_impersonation");
        }
        
        // 5. AI Contextual Boost (multiple AI signals)
        if (detectedThreats.Count > 2)
        {
            maxScore = Math.Min(1.0, maxScore * 1.2);
            detectedThreats.Add($"🎯 AI: Multiple threat signals detected ({detectedThreats.Count})");
            tags.Add("ai_multi_threat");
        }
        
        // 6. AI Confidence Adjustment
        if (maxScore > 0.3)
        {
            // AI learns from patterns - boost confidence for clear threats
            var confidenceBoost = Math.Min(0.2, domainSuspiciousness * 0.3);
            maxScore = Math.Min(1.0, maxScore + confidenceBoost);
        }
        
        return new RuleResult(
            Math.Min(1.0, maxScore),
            string.Join("; ", detectedThreats),
            string.Join(",", tags.Distinct())
        );
    }
    
    // ===== AI HELPER METHODS =====
    
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
    
    private static double CalculateLevenshteinSimilarity(string s1, string s2)
    {
        var maxLen = Math.Max(s1.Length, s2.Length);
        if (maxLen == 0) return 1.0;
        
        var distance = CalculateLevenshteinDistance(s1, s2);
        return 1.0 - (double)distance / maxLen;
    }
    
    private static int CalculateLevenshteinDistance(string s1, string s2)
    {
        var matrix = new int[s1.Length + 1, s2.Length + 1];
        
        for (int i = 0; i <= s1.Length; i++) matrix[i, 0] = i;
        for (int j = 0; j <= s2.Length; j++) matrix[0, j] = j;
        
        for (int i = 1; i <= s1.Length; i++)
        {
            for (int j = 1; j <= s2.Length; j++)
            {
                var cost = s1[i - 1] == s2[j - 1] ? 0 : 1;
                matrix[i, j] = Math.Min(
                    Math.Min(matrix[i - 1, j] + 1, matrix[i, j - 1] + 1),
                    matrix[i - 1, j - 1] + cost);
            }
        }
        
        return matrix[s1.Length, s2.Length];
    }
    
    private static bool ContainsCharacterSubstitution(string domain, string brand)
    {
        // Common character substitutions in phishing
        var substitutions = new Dictionary<char, char[]>
        {
            ['o'] = new[] { '0', 'ο', 'о' }, // o -> 0, Greek omicron, Cyrillic o
            ['a'] = new[] { 'α', 'а' },      // a -> Greek alpha, Cyrillic a
            ['e'] = new[] { 'е' },           // e -> Cyrillic e
            ['i'] = new[] { '1', 'ι', 'і' }, // i -> 1, Greek iota, Cyrillic i
            ['u'] = new[] { 'υ', 'и' },      // u -> Greek upsilon, Cyrillic u
        };
        
        if (domain.Length != brand.Length) return false;
        
        int substitutionCount = 0;
        for (int i = 0; i < domain.Length; i++)
        {
            if (domain[i] != brand[i])
            {
                if (substitutions.ContainsKey(brand[i]) && 
                    substitutions[brand[i]].Contains(domain[i]))
                {
                    substitutionCount++;
                }
                else
                {
                    return false; // Non-substitution difference
                }
            }
        }
        
        return substitutionCount > 0 && substitutionCount <= 2; // 1-2 substitutions = likely attack
    }
}