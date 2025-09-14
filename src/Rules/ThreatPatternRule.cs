using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

/// <summary>
/// Comprehensive threat detection rule for common attack patterns
/// Covers multiple threat categories with Vietnamese context
/// </summary>
public sealed class ThreatPatternRule : IRule
{
    // High-risk patterns that should trigger immediate alerts
    private static readonly string[] HighRiskPatterns = {
        // Gambling & Casino
        "casino", "bet365", "188bet", "fun88", "w88", "dafabet", "kubet",
        "cado", "ca-do", "bongda", "cadobong", "keonhacai",
        
        // Crypto scams
        "metamask", "trustwallet", "binance", "coinbase", "crypto", "bitcoin",
        "ethereum", "defi", "nft", "airdrop", "claim",
        
        // Phishing indicators
        "verify-account", "secure-login", "update-security", "confirm-identity",
        "suspended-account", "blocked-account", "verify-now",
        
        // Vietnamese phishing
        "xac-thuc", "mo-khoa", "kich-hoat", "cap-nhat", "bao-mat"
    };
    
    // Medium-risk patterns
    private static readonly string[] MediumRiskPatterns = {
        "free", "bonus", "gift", "win", "prize", "lucky", "promotion",
        "limited", "exclusive", "special", "offer", "deal"
    };
    
    // Suspicious URL patterns
    private static readonly Regex SuspiciousUrlPatterns = new(
        @"(verify|secure|login|update|confirm)[-_]?(now|today|urgent|immediate|fast)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    
    // Vietnamese urgent language
    private static readonly string[] VietnameseUrgent = {
        "khẩn cấp", "ngay lập tức", "hết hạn", "sắp hết hạn",
        "khóa tài khoản", "tạm khóa", "bị khóa"
    };

    public RuleResult Evaluate((string Host, string Path, string? Text) f)
    {
        var host = f.Host.ToLowerInvariant();
        var path = f.Path.ToLowerInvariant();
        var text = (f.Text ?? "").ToLowerInvariant();
        var fullContext = $"{host} {path} {text}";
        
        double score = 0;
        var reasons = new List<string>();
        var tags = new List<string>();

        // Check high-risk patterns
        var highRiskMatches = HighRiskPatterns.Where(pattern => 
            fullContext.Contains(pattern)).ToArray();
            
        if (highRiskMatches.Any())
        {
            score += 0.5;
            reasons.Add($"High-risk patterns detected: {string.Join(", ", highRiskMatches)}");
            
            // Categorize the threat
            if (highRiskMatches.Any(m => new[] {"casino", "bet", "gambling", "cado"}.Contains(m)))
                tags.Add("gambling_threat");
            if (highRiskMatches.Any(m => new[] {"crypto", "bitcoin", "metamask"}.Contains(m)))
                tags.Add("crypto_threat");
            if (highRiskMatches.Any(m => new[] {"verify", "secure", "login"}.Contains(m)))
                tags.Add("phishing_threat");
        }
        
        // Check medium-risk patterns
        var mediumRiskMatches = MediumRiskPatterns.Where(pattern => 
            fullContext.Contains(pattern)).ToArray();
            
        if (mediumRiskMatches.Any())
        {
            score += 0.25;
            reasons.Add($"Suspicious promotional language: {string.Join(", ", mediumRiskMatches)}");
            tags.Add("promotional_scam");
        }
        
        // Check suspicious URL patterns
        if (SuspiciousUrlPatterns.IsMatch(host) || SuspiciousUrlPatterns.IsMatch(path))
        {
            score += 0.35;
            reasons.Add("Suspicious URL pattern designed to create urgency");
            tags.Add("urgent_url_pattern");
        }
        
        // Check Vietnamese urgent language
        var vietnameseUrgentMatches = VietnameseUrgent.Where(pattern => 
            text.Contains(pattern)).ToArray();
            
        if (vietnameseUrgentMatches.Any())
        {
            score += 0.3;
            reasons.Add($"Vietnamese urgent language detected: {string.Join(", ", vietnameseUrgentMatches)}");
            tags.Add("vietnamese_urgency");
        }
        
        // Bonus scoring for multiple threat indicators
        if (tags.Count > 2)
        {
            score += 0.2;
            reasons.Add("Multiple threat indicators detected - highly suspicious");
            tags.Add("multi_threat");
        }

        if (score > 0)
        {
            return new RuleResult(Math.Min(1.0, score), 
                string.Join("; ", reasons), 
                string.Join(",", tags.Distinct()));
        }

        return new RuleResult(0, "", "");
    }
}