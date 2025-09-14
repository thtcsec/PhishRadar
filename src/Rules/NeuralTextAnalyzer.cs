using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using PhishRadar.Core.Models;

namespace PhishRadar.Rules;

/// <summary>
/// Neural Network-inspired text analysis for phishing detection
/// Implements attention mechanisms and semantic analysis
/// </summary>
public sealed class NeuralTextAnalyzer
{
    private static readonly Dictionary<string, double> VietnamesePhishingWeights = new()
    {
        // Banking terms
        { "ngân hàng", 0.3 }, { "tài khoản", 0.4 }, { "mật khẩu", 0.5 },
        { "otp", 0.7 }, { "xác thực", 0.6 }, { "đăng nhập", 0.4 },
        
        // Urgency terms
        { "khẩn cấp", 0.8 }, { "ngay lập tức", 0.7 }, { "hết hạn", 0.6 },
        { "tạm khóa", 0.8 }, { "bị khóa", 0.8 }, { "cảnh báo", 0.5 },
        
        // Scam terms
        { "trúng thưởng", 0.9 }, { "khuyến mãi", 0.4 }, { "miễn phí", 0.3 },
        { "click ngay", 0.6 }, { "limited time", 0.5 }
    };
    
    private static readonly Dictionary<string, double> EnglishPhishingWeights = new()
    {
        { "verify", 0.6 }, { "suspend", 0.7 }, { "urgent", 0.6 },
        { "click here", 0.5 }, { "act now", 0.7 }, { "limited time", 0.5 },
        { "congratulations", 0.4 }, { "winner", 0.6 }, { "claim", 0.5 }
    };

    /// <summary>
    /// Attention-based text analysis - focuses on important phrases
    /// </summary>
    public static (double score, string[] detectedPhrases) AnalyzeWithAttention(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return (0, Array.Empty<string>());
        
        var normalizedText = text.ToLowerInvariant();
        var detectedPhrases = new List<string>();
        double totalScore = 0;
        
        // Vietnamese analysis with attention weights
        foreach (var (phrase, weight) in VietnamesePhishingWeights)
        {
            if (normalizedText.Contains(phrase))
            {
                detectedPhrases.Add(phrase);
                totalScore += weight;
            }
        }
        
        // English analysis
        foreach (var (phrase, weight) in EnglishPhishingWeights)
        {
            if (normalizedText.Contains(phrase))
            {
                detectedPhrases.Add(phrase);
                totalScore += weight * 0.8; // Slightly lower weight for English in VN context
            }
        }
        
        // Apply attention mechanism - boost score for multiple co-occurring terms
        if (detectedPhrases.Count > 1)
        {
            totalScore *= (1 + Math.Log(detectedPhrases.Count) * 0.2);
        }
        
        return (Math.Min(1.0, totalScore), detectedPhrases.ToArray());
    }
    
    /// <summary>
    /// Semantic similarity detection using vector space model
    /// </summary>
    public static double CalculateSemanticSimilarity(string text1, string text2)
    {
        if (string.IsNullOrWhiteSpace(text1) || string.IsNullOrWhiteSpace(text2))
            return 0;
            
        var words1 = ExtractWords(text1);
        var words2 = ExtractWords(text2);
        
        var commonWords = words1.Intersect(words2).Count();
        var totalWords = words1.Union(words2).Count();
        
        return totalWords > 0 ? (double)commonWords / totalWords : 0;
    }
    
    /// <summary>
    /// Context-aware sentiment analysis for phishing detection
    /// </summary>
    public static (double urgencyScore, double trustScore) AnalyzeSentiment(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return (0, 0);
        
        var normalizedText = text.ToLowerInvariant();
        
        // Urgency indicators
        var urgencyKeywords = new[] 
        {
            "khẩn", "ngay", "immediately", "urgent", "expire", "deadline",
            "hết hạn", "nhanh", "immediately", "asap"
        };
        
        // Trust indicators
        var trustKeywords = new[]
        {
            "official", "secure", "verified", "legitimate", "authentic",
            "chính thức", "an toàn", "bảo mật", "xác thực"
        };
        
        var urgencyScore = urgencyKeywords.Count(keyword => normalizedText.Contains(keyword)) / 10.0;
        var trustScore = trustKeywords.Count(keyword => normalizedText.Contains(keyword)) / 10.0;
        
        // Normalize scores
        urgencyScore = Math.Min(1.0, urgencyScore);
        trustScore = Math.Min(1.0, trustScore);
        
        return (urgencyScore, trustScore);
    }
    
    /// <summary>
    /// Advanced pattern recognition using regex neural patterns
    /// </summary>
    public static (bool hasPhishingPattern, string[] patterns) DetectAdvancedPatterns(string? content)
    {
        if (string.IsNullOrWhiteSpace(content)) return (false, Array.Empty<string>());
        
        var detectedPatterns = new List<string>();
        
        // Neural-inspired regex patterns
        var patterns = new Dictionary<string, Regex>
        {
            ["phone_harvesting"] = new(@"\b(0[3-9]\d{8}|84[3-9]\d{8})\b", RegexOptions.Compiled),
            ["bank_account"] = new(@"\b\d{9,16}\b", RegexOptions.Compiled),
            ["urgency_caps"] = new(@"\b[A-Z]{3,}\b.*?(NGAY|NOW|URGENT)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["fake_countdown"] = new(@"\d+\s*(giây|phút|giờ|second|minute|hour).*?(còn lại|remaining)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            ["authority_impersonation"] = new(@"(ngân hàng|police|chính phủ|government).*?(thông báo|notification)", RegexOptions.Compiled | RegexOptions.IgnoreCase)
        };
        
        foreach (var (patternName, regex) in patterns)
        {
            if (regex.IsMatch(content))
            {
                detectedPatterns.Add(patternName);
            }
        }
        
        return (detectedPatterns.Count > 0, detectedPatterns.ToArray());
    }
    
    private static HashSet<string> ExtractWords(string text)
    {
        return new HashSet<string>(
            text.ToLowerInvariant()
                .Split(' ', '\t', '\n', '\r', '.', ',', '!', '?', ';', ':')
                .Where(word => word.Length > 2)
                .Select(word => word.Trim())
        );
    }
}