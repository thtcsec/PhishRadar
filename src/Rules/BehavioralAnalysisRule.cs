using PhishRadar.Core.Abstractions;
using System.Text.RegularExpressions;

namespace PhishRadar.Rules;

/// <summary>
/// Behavioral Analysis Engine - Analyzes user interaction patterns and psychological manipulation
/// Detects advanced social engineering and behavioral targeting
/// </summary>
public sealed class BehavioralAnalysisRule : IRule
{
    // Psychological manipulation patterns
    private static readonly Dictionary<string, double> PsychologyTriggers = new()
    {
        // Authority triggers
        ["authority"] = 0.7,
        ["official"] = 0.6,
        ["government"] = 0.7,
        ["police"] = 0.8,
        ["bank manager"] = 0.8,
        ["chính thức"] = 0.6,
        ["chính phủ"] = 0.7,
        ["cảnh sát"] = 0.8,
        ["quản lý ngân hàng"] = 0.8,

        // Urgency triggers
        ["urgent"] = 0.6,
        ["immediate"] = 0.7,
        ["emergency"] = 0.8,
        ["expires today"] = 0.9,
        ["khẩn cấp"] = 0.6,
        ["ngay lập tức"] = 0.7,
        ["khẩn cấp"] = 0.8,
        ["hết hạn hôm nay"] = 0.9,

        // Scarcity triggers
        ["limited time"] = 0.6,
        ["only today"] = 0.7,
        ["last chance"] = 0.8,
        ["thời gian có hạn"] = 0.6,
        ["chỉ hôm nay"] = 0.7,
        ["cơ hội cuối"] = 0.8,

        // Fear triggers
        ["account suspended"] = 0.8,
        ["security breach"] = 0.9,
        ["fraud detected"] = 0.9,
        ["tài khoản bị khóa"] = 0.8,
        ["vi phạm bảo mật"] = 0.9,
        ["phát hiện gian lận"] = 0.9,

        // Reward triggers
        ["congratulations"] = 0.6,
        ["winner"] = 0.7,
        ["bonus"] = 0.5,
        ["free"] = 0.4,
        ["chúc mừng"] = 0.6,
        ["người thắng"] = 0.7,
        ["thưởng"] = 0.5,
        ["miễn phí"] = 0.4
    };

    // Interaction pressure patterns
    private static readonly Regex[] PressurePatterns = {
        new(@"click\s+(here|now|immediately)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"(nhấn|click)\s+(vào đây|ngay|lập tức)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"call\s+(now|immediately|\d{3}-\d{3}-\d{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"(gọi|call)\s+(ngay|lập tức|\d{3}-\d{3}-\d{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"verify\s+(now|immediately|within|trong)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"(xác thực|verify)\s+(ngay|lập tức|trong)", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    };

    // Vietnamese cultural context patterns
    private static readonly string[] VietnameseCulturalPhrases = {
        "anh chị", "quý khách", "kính thưa", "thân mến",
        "xin chào", "trân trọng", "kính gửi", "cảm ơn quý khách"
    };

    // Gambling behavioral patterns (specific to Vietnam)
    private static readonly Dictionary<string, double> GamblingBehaviorPatterns = new()
    {
        ["easy money"] = 0.8,
        ["quick profit"] = 0.8,
        ["guaranteed win"] = 0.9,
        ["sure bet"] = 0.9,
        ["tiền dễ"] = 0.8,
        ["lợi nhuận nhanh"] = 0.8,
        ["thắng chắc"] = 0.9,
        ["cược chắc thắng"] = 0.9,
        ["rich quick"] = 0.8,
        ["giàu nhanh"] = 0.8
    };

    public RuleResult Evaluate((string Host, string Path, string? Text) features)
    {
        double score = 0;
        var reasons = new List<string>();
        var tags = new List<string>();

        var host = features.Host.ToLowerInvariant();
        var text = (features.Text ?? "").ToLowerInvariant();
        var combinedContent = $"{host} {features.Path} {text}";

        // 1. PSYCHOLOGICAL MANIPULATION ANALYSIS
        var (psychScore, psychTriggers) = AnalyzePsychologicalTriggers(combinedContent);
        if (psychScore > 0)
        {
            score = Math.Max(score, psychScore);
            reasons.Add($"🧠 Psychological manipulation: {string.Join(", ", psychTriggers)}");
            tags.Add("psychological_manipulation");
        }

        // 2. INTERACTION PRESSURE DETECTION
        var pressureScore = AnalyzeInteractionPressure(text);
        if (pressureScore > 0)
        {
            score = Math.Max(score, pressureScore);
            reasons.Add("⚡ High-pressure interaction tactics detected");
            tags.Add("pressure_tactics");
        }

        // 3. CULTURAL CONTEXT ABUSE
        var culturalScore = AnalyzeCulturalManipulation(text);
        if (culturalScore > 0)
        {
            score = Math.Max(score, culturalScore);
            reasons.Add("🇻🇳 Vietnamese cultural context manipulation");
            tags.Add("cultural_manipulation");
        }

        // 4. GAMBLING BEHAVIORAL ANALYSIS
        var (gamblingScore, gamblingPatterns) = AnalyzeGamblingBehavior(combinedContent);
        if (gamblingScore > 0)
        {
            score = Math.Max(score, gamblingScore);
            reasons.Add($"🎰 Gambling behavioral patterns: {string.Join(", ", gamblingPatterns)}");
            tags.Add("gambling_behavioral");
        }

        // 5. EMOTIONAL MANIPULATION DETECTION
        var emotionalScore = AnalyzeEmotionalManipulation(text);
        if (emotionalScore > 0)
        {
            score = Math.Max(score, emotionalScore);
            reasons.Add("😨 Emotional manipulation tactics detected");
            tags.Add("emotional_manipulation");
        }

        // 6. TRUST EXPLOITATION ANALYSIS
        var trustScore = AnalyzeTrustExploitation(host, text);
        if (trustScore > 0)
        {
            score = Math.Max(score, trustScore);
            reasons.Add("🤝 Trust exploitation detected");
            tags.Add("trust_exploitation");
        }

        // 7. BEHAVIORAL CLUSTERING (Multiple patterns = higher confidence)
        if (tags.Count > 2)
        {
            score = Math.Min(1.0, score * 1.3); // Boost for multiple behavioral patterns
            reasons.Add($"🎯 Multiple behavioral manipulation patterns ({tags.Count} detected)");
            tags.Add("behavioral_cluster");
        }

        return new RuleResult(
            Math.Min(1.0, score),
            string.Join("; ", reasons),
            string.Join(",", tags.Distinct())
        );
    }

    private (double score, List<string> triggers) AnalyzePsychologicalTriggers(string content)
    {
        var detectedTriggers = new List<string>();
        double maxScore = 0;

        foreach (var (trigger, score) in PsychologyTriggers)
        {
            if (content.Contains(trigger))
            {
                detectedTriggers.Add(trigger);
                maxScore = Math.Max(maxScore, score);
            }
        }

        // Boost score for multiple triggers
        if (detectedTriggers.Count > 2)
        {
            maxScore = Math.Min(1.0, maxScore * 1.2);
        }

        return (maxScore, detectedTriggers);
    }

    private double AnalyzeInteractionPressure(string text)
    {
        int pressureCount = PressurePatterns.Count(pattern => pattern.IsMatch(text));

        return pressureCount switch
        {
            >= 3 => 0.8, // High pressure
            2 => 0.6,    // Medium pressure
            1 => 0.4,    // Low pressure
            _ => 0       // No pressure
        };
    }

    private double AnalyzeCulturalManipulation(string text)
    {
        // Detect abuse of Vietnamese politeness culture
        var politenessPhrases = VietnameseCulturalPhrases.Count(phrase => text.Contains(phrase));
        
        // High politeness + urgency = manipulation
        if (politenessPhrases > 1 && (text.Contains("khẩn cấp") || text.Contains("urgent")))
        {
            return 0.7;
        }

        // Excessive politeness (potential manipulation)
        if (politenessPhrases > 3)
        {
            return 0.5;
        }

        return 0;
    }

    private (double score, List<string> patterns) AnalyzeGamblingBehavior(string content)
    {
        var detectedPatterns = new List<string>();
        double maxScore = 0;

        foreach (var (pattern, score) in GamblingBehaviorPatterns)
        {
            if (content.Contains(pattern))
            {
                detectedPatterns.Add(pattern);
                maxScore = Math.Max(maxScore, score);
            }
        }

        return (maxScore, detectedPatterns);
    }

    private double AnalyzeEmotionalManipulation(string text)
    {
        // Fear-based manipulation
        var fearWords = new[] { "afraid", "scared", "lose", "risk", "danger", "sợ", "mất", "nguy hiểm", "rủi ro" };
        var fearCount = fearWords.Count(word => text.Contains(word));

        // Greed-based manipulation  
        var greedWords = new[] { "money", "profit", "rich", "wealthy", "tiền", "lợi nhuận", "giàu", "sang" };
        var greedCount = greedWords.Count(word => text.Contains(word));

        if (fearCount > 2 || greedCount > 2)
            return 0.7;
        if (fearCount > 0 && greedCount > 0)
            return 0.6; // Fear + Greed combination

        return 0;
    }

    private double AnalyzeTrustExploitation(string host, string text)
    {
        // Brand impersonation attempt
        var trustBrands = new[] { 
            "bank", "google", "microsoft", "facebook", "government",
            "ngân hàng", "chính phủ", "nhà nước"
        };

        var brandMentions = trustBrands.Count(brand => 
            host.Contains(brand) || text.Contains(brand));

        // Security theater (fake security language)
        var securityTheater = new[] {
            "secure connection", "verified", "trusted", "certified", "ssl",
            "kết nối an toàn", "đã xác thực", "đáng tin cậy", "chứng nhận"
        };

        var securityMentions = securityTheater.Count(term => text.Contains(term));

        if (brandMentions > 1 && securityMentions > 1)
            return 0.8; // High trust exploitation

        return 0;
    }
}