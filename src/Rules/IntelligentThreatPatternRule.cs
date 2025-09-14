using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

/// <summary>
/// Intelligent Threat Pattern Analyzer - Advanced AI-powered pattern recognition
/// Detects sophisticated phishing techniques and social engineering
/// </summary>
public sealed class IntelligentThreatPatternRule : IRule
{
    // Advanced phishing patterns
    private static readonly Dictionary<string, (Regex Pattern, double Score, string Description)> ThreatPatterns = new()
    {
        ["urgent_banking"] = (
            new Regex(@"(urgent|khẩn cấp).{0,50}(bank|ngân hàng|account|tài khoản)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.8, "Urgent banking social engineering"
        ),
        ["fake_security_alert"] = (
            new Regex(@"(security alert|cảnh báo bảo mật).{0,30}(verify|xác thực|update|cập nhật)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.7, "Fake security alert pattern"
        ),
        ["account_suspension"] = (
            new Regex(@"(suspend|khóa|block|chặn).{0,30}(account|tài khoản).{0,30}(verify|click|xác thực)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.8, "Account suspension threat"
        ),
        ["otp_harvesting"] = (
            new Regex(@"(enter|nhập).{0,20}(otp|mã).{0,30}(verify|xác thực|confirm|xác nhận)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.9, "OTP harvesting attempt"
        ),
        ["time_pressure"] = (
            new Regex(@"(expire|hết hạn|deadline).{0,20}(hour|giờ|minute|phút|day|ngày)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.6, "Time pressure manipulation"
        ),
        ["fake_prize"] = (
            new Regex(@"(congratulation|chúc mừng|winner|trúng).{0,50}(prize|giải thưởng|claim|nhận)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.7, "Fake prize/lottery scam"
        ),
        ["credential_phishing"] = (
            new Regex(@"(login|đăng nhập).{0,30}(verify|xác thực).{0,30}(identity|danh tính|credential)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.8, "Credential phishing attempt"
        ),
        ["authority_impersonation"] = (
            new Regex(@"(police|cảnh sát|government|chính phủ|bank|ngân hàng).{0,30}(official|chính thức).{0,30}(notice|thông báo)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.8, "Authority impersonation"
        ),
        ["vietnamese_scam_phrases"] = (
            new Regex(@"(cần gấp|khẩn cấp|ngay lập tức).{0,30}(xác thực|verify|update|cập nhật)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.7, "Vietnamese urgency scam phrases"
        )
    };

    // Sophisticated domain patterns
    private static readonly Dictionary<string, (Regex Pattern, double Score, string Description)> DomainPatterns = new()
    {
        ["typosquatting_bank"] = (
            new Regex(@"(viet-com|tech-com|vietin-bank|bi-dv|v-cb|t-cb)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.9, "Vietnamese bank typosquatting"
        ),
        ["suspicious_subdomain"] = (
            new Regex(@"(secure|security|verify|update|login)\.([\w-]+\.)+\w+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.6, "Suspicious security-themed subdomain"
        ),
        ["bank_with_number"] = (
            new Regex(@"(vietcombank|techcombank|bidv|acb)\d+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.8, "Bank name with numbers (suspicious)"
        ),
        ["gambling_domain"] = (
            new Regex(@"(bet|casino|poker|slot)\d*\.(tk|ml|ga|cf|club|xyz)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.9, "Gambling domain with suspicious TLD"
        ),
        // CRITICAL: Vietnamese casino patterns
        ["vietnamese_casino_nohu"] = (
            new Regex(@"(nohu|no-hu|nohutop|gamebai|game-bai)\d*", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.95, "Vietnamese casino/nổ hũ site pattern"
        ),
        ["casino_number_pattern"] = (
            new Regex(@"(nohu|bai|game|casino|slot)\d+|" +
                     @"\d+(win|bet|game|casino|nohu|bai)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.9, "Casino with number pattern (nohu90, game88, etc.)"
        ),
        ["vietnamese_gambling_slang"] = (
            new Regex(@"(doi-thuong|doithuong|an-tien|antien|bai-doi-thuong)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            0.85, "Vietnamese gambling slang in domain"
        )
    };

    // Behavioral indicators
    private static readonly string[] SocialEngineeringTriggers = {
        "act now", "limited time", "urgent action required", "verify immediately",
        "hành động ngay", "thời gian có hạn", "yêu cầu khẩn cấp", "xác thực ngay lập tức",
        "click here", "download now", "call now", "update required",
        "nhấn vào đây", "tải về ngay", "gọi ngay", "cần cập nhật"
    };

    public RuleResult Evaluate((string Host, string Path, string? Text) features)
    {
        double maxScore = 0;
        var detectedThreats = new List<string>();
        var tags = new HashSet<string>();

        var host = features.Host.ToLowerInvariant();
        var path = features.Path.ToLowerInvariant();
        var text = (features.Text ?? "").ToLowerInvariant();
        var combinedContent = $"{host} {path} {text}";

        // 1. ADVANCED PATTERN ANALYSIS
        foreach (var (name, (pattern, score, description)) in ThreatPatterns)
        {
            if (pattern.IsMatch(combinedContent))
            {
                maxScore = Math.Max(maxScore, score);
                detectedThreats.Add($"🚨 {description}");
                tags.Add($"threat_{name}");
            }
        }

        // 2. DOMAIN PATTERN ANALYSIS
        var domainToCheck = $"{host}{path}";
        foreach (var (name, (pattern, score, description)) in DomainPatterns)
        {
            if (pattern.IsMatch(domainToCheck))
            {
                maxScore = Math.Max(maxScore, score);
                detectedThreats.Add($"🎭 {description}");
                tags.Add($"domain_{name}");
            }
        }

        // 3. SOCIAL ENGINEERING DETECTION
        var socialEngineeringCount = SocialEngineeringTriggers.Count(trigger => 
            combinedContent.Contains(trigger));
        
        if (socialEngineeringCount > 2)
        {
            maxScore = Math.Max(maxScore, 0.7);
            detectedThreats.Add($"🧠 Social engineering: {socialEngineeringCount} manipulation triggers");
            tags.Add("social_engineering");
        }
        else if (socialEngineeringCount > 0)
        {
            maxScore = Math.Max(maxScore, 0.4);
            detectedThreats.Add($"⚠️ Persuasion tactics detected: {socialEngineeringCount} triggers");
            tags.Add("persuasion_tactics");
        }

        // 4. VIETNAMESE-SPECIFIC INTELLIGENCE
        var vietnameseScore = AnalyzeVietnameseContext(combinedContent);
        if (vietnameseScore > 0)
        {
            maxScore = Math.Max(maxScore, vietnameseScore);
            detectedThreats.Add("🇻🇳 Vietnamese-specific threat pattern");
            tags.Add("vietnamese_specific");
        }

        // 5. MULTI-VECTOR ANALYSIS
        var vectorCount = CountAttackVectors(host, path, text);
        if (vectorCount > 2)
        {
            maxScore = Math.Max(maxScore, 0.6);
            detectedThreats.Add($"🎯 Multi-vector attack: {vectorCount} attack vectors");
            tags.Add("multi_vector");
        }

        // 6. CONFIDENCE BOOSTING
        if (detectedThreats.Count > 2)
        {
            maxScore = Math.Min(1.0, maxScore * 1.2); // Boost confidence
            tags.Add("high_confidence");
        }

        return new RuleResult(
            Math.Min(1.0, maxScore),
            string.Join("; ", detectedThreats),
            string.Join(",", tags.Distinct())
        );
    }

    private double AnalyzeVietnameseContext(string content)
    {
        // Vietnamese banking context
        var vietnameseBankingPhrases = new[]
        {
            "tài khoản ngân hàng", "chuyển khoản", "số dư tài khoản",
            "thẻ tín dụng", "mã pin", "mã otp", "bảo mật ngân hàng"
        };

        // Vietnamese urgency context
        var vietnameseUrgencyPhrases = new[]
        {
            "khẩn cấp", "ngay lập tức", "hết hạn", "sắp hết hạn",
            "cần gấp", "thời gian có hạn", "deadline"
        };

        var bankingCount = vietnameseBankingPhrases.Count(phrase => content.Contains(phrase));
        var urgencyCount = vietnameseUrgencyPhrases.Count(phrase => content.Contains(phrase));

        if (bankingCount > 0 && urgencyCount > 0)
            return 0.8; // High risk: Banking + Urgency
        if (bankingCount > 1)
            return 0.6; // Medium risk: Multiple banking terms
        if (urgencyCount > 1)
            return 0.4; // Low-medium risk: Multiple urgency terms

        return 0;
    }

    private int CountAttackVectors(string host, string path, string text)
    {
        int vectors = 0;

        // URL vector
        if (host.Contains("-") || host.Contains("security") || host.Contains("verify"))
            vectors++;

        // Path vector
        if (path.Contains("login") || path.Contains("verify") || path.Contains("update"))
            vectors++;

        // Content vector
        if (text.Contains("otp") || text.Contains("password") || text.Contains("verify"))
            vectors++;

        // Social engineering vector
        if (SocialEngineeringTriggers.Any(trigger => text.Contains(trigger)))
            vectors++;

        return vectors;
    }
}