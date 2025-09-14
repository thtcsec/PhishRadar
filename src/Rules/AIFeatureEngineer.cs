using System;
using System.Linq;
using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;
using PhishRadar.Core.Models;

namespace PhishRadar.Rules;

/// <summary>
/// AI-powered feature engineering for enhanced phishing detection
/// Uses advanced mathematical and linguistic analysis
/// </summary>
public sealed class AIFeatureEngineer
{
    private static readonly Regex SpecialCharPattern = new(@"[^a-zA-Z0-9.-]", RegexOptions.Compiled);
    private static readonly Regex SubdomainPattern = new(@"^([^.]+\.)+", RegexOptions.Compiled);
    private static readonly string[] SuspiciousTlds = { ".tk", ".ml", ".ga", ".cf", ".club", ".xyz", ".top", ".click" };
    
    /// <summary>
    /// Calculate Shannon entropy for domain randomness detection
    /// </summary>
    public static double CalculateEntropy(string input)
    {
        if (string.IsNullOrEmpty(input)) return 0;
        
        var frequencies = input.GroupBy(c => c)
            .ToDictionary(g => g.Key, g => (double)g.Count() / input.Length);
            
        return -frequencies.Values.Sum(p => p * Math.Log2(p));
    }
    
    /// <summary>
    /// Detect suspicious character patterns using AI heuristics
    /// </summary>
    public static (int count, double ratio) AnalyzeCharacterPatterns(string domain)
    {
        var specialChars = SpecialCharPattern.Matches(domain).Count;
        var totalChars = domain.Length;
        var ratio = totalChars > 0 ? (double)specialChars / totalChars : 0;
        
        return (specialChars, ratio);
    }
    
    /// <summary>
    /// Advanced subdomain analysis
    /// </summary>
    public static (int count, bool suspicious) AnalyzeSubdomains(string host)
    {
        var parts = host.Split('.');
        var subdomainCount = Math.Max(0, parts.Length - 2); // Exclude domain and TLD
        
        // Suspicious patterns: too many subdomains or random-looking subdomains
        var suspicious = subdomainCount > 3 || 
                        parts.Any(part => part.Length > 15 || CalculateEntropy(part) > 3.5);
        
        return (subdomainCount, suspicious);
    }
    
    /// <summary>
    /// Domain age estimation using heuristics
    /// </summary>
    public static bool EstimateNewDomain(string domain)
    {
        // Heuristics for newly registered domains
        var entropy = CalculateEntropy(domain);
        var hasNumbers = domain.Any(char.IsDigit);
        var hasHyphens = domain.Contains('-');
        var suspiciousTld = SuspiciousTlds.Any(tld => domain.EndsWith(tld));
        
        // High entropy + numbers + hyphens + suspicious TLD = likely new domain
        return entropy > 3.0 && hasNumbers && hasHyphens && suspiciousTld;
    }
    
    /// <summary>
    /// Content complexity analysis for AI feature engineering
    /// </summary>
    public static (double complexity, bool suspicious) AnalyzeContentComplexity(string? content)
    {
        if (string.IsNullOrWhiteSpace(content)) return (0, false);
        
        var text = content.ToLowerInvariant();
        var wordCount = text.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length;
        var sentenceCount = text.Split('.', '!', '?').Length;
        var avgWordsPerSentence = sentenceCount > 0 ? (double)wordCount / sentenceCount : 0;
        
        // Suspicious: very short content with urgent language
        var urgentWords = new[] { "urgent", "immediate", "verify", "suspend", "expire", "khẩn", "ngay" };
        var urgentCount = urgentWords.Count(word => text.Contains(word));
        
        var complexity = avgWordsPerSentence * (1 + urgentCount * 0.5);
        var suspicious = wordCount < 50 && urgentCount > 2; // Short + urgent = suspicious
        
        return (complexity, suspicious);
    }
    
    /// <summary>
    /// Enhanced feature vector for ML with AI-derived features
    /// </summary>
    public static float[] CreateAIFeatureVector(AdvancedFeatures features)
    {
        var entropy = CalculateEntropy(features.Host);
        var (specialChars, specialRatio) = AnalyzeCharacterPatterns(features.Host);
        var (subdomains, suspiciousSubdomains) = AnalyzeSubdomains(features.Host);
        var newDomain = EstimateNewDomain(features.Host);
        var (contentComplexity, suspiciousContent) = AnalyzeContentComplexity(features.ContentText);
        
        return new float[]
        {
            // Original features
            features.UrlLength,
            features.HostLength,
            features.PathLength,
            features.HyphenCount,
            features.DigitCount,
            
            // AI-enhanced features
            (float)entropy,
            (float)specialRatio,
            subdomains,
            suspiciousSubdomains ? 1f : 0f,
            newDomain ? 1f : 0f,
            (float)contentComplexity,
            suspiciousContent ? 1f : 0f,
            
            // Security features
            features.HasHttpsRedirect ? 1f : 0f,
            features.HasValidCertificate ? 1f : 0f,
            features.IsSuspiciousTld ? 1f : 0f,
            
            // Vietnamese-specific AI features
            features.IsVietnameseBankDomain ? 1f : 0f,
            features.HasVietnamesePhishingKeywords ? 1f : 0f,
            features.VietnameseThreats.Length,
            
            // Network intelligence
            features.RedirectCount,
            features.IpAddresses.Length
        };
    }
}