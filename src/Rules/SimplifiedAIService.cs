using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PhishRadar.Core.Abstractions;
using PhishRadar.Core.Models;
using System.Collections.Concurrent;

namespace PhishRadar.Rules;

/// <summary>
/// Simplified AI Service for production use without complex dependencies
/// </summary>
public sealed class SimplifiedAIService : IMlScorer, IDisposable
{
    private readonly Random _random = new(42);
    
    // Performance caching
    private readonly ConcurrentDictionary<string, (double score, DateTime cached)> _scoreCache = new();
    private readonly TimeSpan _cacheExpiry = TimeSpan.FromMinutes(5);

    public SimplifiedAIService()
    {
        Console.WriteLine("🤖 Simplified AI Service initialized");
    }

    public Task<double> ScoreAsync(float[] vector, CancellationToken ct = default)
    {
        if (vector == null || vector.Length == 0)
            return Task.FromResult(0.0);

        // Check cache first
        var cacheKey = string.Join(",", vector.Take(7)); // Use first 7 features for caching
        if (_scoreCache.TryGetValue(cacheKey, out var cached) && 
            DateTime.UtcNow - cached.cached < _cacheExpiry)
        {
            return Task.FromResult(cached.score);
        }

        // Intelligent heuristic scoring
        var score = CalculateIntelligentScore(vector);

        // Cache the result
        _scoreCache.TryAdd(cacheKey, (score, DateTime.UtcNow));

        return Task.FromResult(Math.Max(0, Math.Min(1.0, score)));
    }

    /// <summary>
    /// Advanced scoring with explainability for enhanced models
    /// </summary>
    public Task<(double score, Dictionary<string, double> featureContributions)> ScoreAdvancedWithExplainabilityAsync(
        AdvancedFeatures features, CancellationToken ct = default)
    {
        var vector = features.NumericalFeatures.Length > 0 
            ? features.NumericalFeatures 
            : new EnhancedFeaturizer().Vectorize(features);

        var score = CalculateIntelligentScore(vector);
        var contributions = CalculateFeatureContributions(vector, features);

        return Task.FromResult((score, contributions));
    }

    private Dictionary<string, double> CalculateFeatureContributions(float[] vector, AdvancedFeatures features)
    {
        var contributions = new Dictionary<string, double>();

        if (vector.Length >= 7)
        {
            // Standard model features with contributions
            if (vector[0] > 80) contributions["URL_Length_Long"] = NormalizeContribution(vector[0], 150, 0.15);
            if (vector[1] > 0) contributions["Hyphen_Count"] = NormalizeContribution(vector[1], 5, 0.20);
            if (vector[2] > 0) contributions["Digit_Count"] = NormalizeContribution(vector[2], 15, 0.18);
            if (vector[3] > 2) contributions["Subdomain_Count"] = NormalizeContribution(vector[3], 5, 0.25);
            if (vector[4] > 3) contributions["Path_Depth"] = NormalizeContribution(vector[4], 10, 0.15);
            if (vector[5] > 0) contributions["Vietnamese_Phishing_Keywords"] = 0.40;
            if (vector[6] > 0) contributions["Vietnamese_Bank_Domain"] = 0.45;
        }

        // Advanced feature contributions
        if (features.IsSuspiciousTld)
            contributions["Suspicious_TLD"] = 0.35;
        if (features.HasPunycode)
            contributions["Punycode_Attack"] = 0.30;
        if (features.HasVietnamesePhishingKeywords)
            contributions["Vietnamese_Phishing"] = 0.40;
        if (features.Protocol == "http")
            contributions["Insecure_HTTP"] = 0.25;
        if (features.HasVietnameseGamblingKeywords)
            contributions["Vietnamese_Gambling"] = 0.50;

        // Vietnamese-specific threats
        if (features.VietnameseThreats.Length > 0)
        {
            foreach (var threat in features.VietnameseThreats.Take(3))
            {
                contributions[$"VN_Threat_{threat}"] = 0.20;
            }
        }

        // Return only significant contributions
        return contributions
            .Where(x => x.Value > 0.1)
            .OrderByDescending(x => x.Value)
            .Take(8)
            .ToDictionary(x => x.Key, x => x.Value);
    }

    private double NormalizeContribution(float value, float maxExpected, double weight)
    {
        var normalized = Math.Min(1.0, value / maxExpected);
        return normalized * weight;
    }

    private double CalculateIntelligentScore(float[] vector)
    {
        if (vector.Length < 7) return 0;

        // Enhanced heuristic scoring based on cybersecurity research
        double score = 0;

        // URL Length Analysis (0-150 normal, 150+ suspicious)
        var urlLength = vector[0];
        if (urlLength > 80) score += 0.1;
        if (urlLength > 120) score += 0.15;
        if (urlLength > 180) score += 0.2;

        // Hyphen Count (1-2 normal, 3+ suspicious)
        var hyphenCount = vector[1];
        if (hyphenCount > 2) score += 0.2;
        if (hyphenCount > 4) score += 0.3;

        // Digit Count (0-5 normal, 6+ suspicious)
        var digitCount = vector[2];
        if (digitCount > 5) score += 0.15;
        if (digitCount > 10) score += 0.25;

        // Subdomain Count (1-2 normal, 3+ suspicious)
        var subdomainCount = vector[3];
        if (subdomainCount > 3) score += 0.25;
        if (subdomainCount > 5) score += 0.35;

        // Path Depth (1-3 normal, 4+ suspicious)
        var pathDepth = vector[4];
        if (pathDepth > 4) score += 0.15;
        if (pathDepth > 7) score += 0.25;

        // Vietnamese Phishing Keywords (Binary)
        if (vector[5] > 0) score += 0.4;

        // Vietnamese Bank Domain (Binary)
        if (vector[6] > 0) score += 0.45;

        // Advanced features if available
        if (vector.Length > 7)
        {
            // Host Length
            var hostLength = vector[7];
            if (hostLength > 30) score += 0.1;
            if (hostLength > 50) score += 0.15;

            // Suspicious TLD (Binary)
            if (vector.Length > 13 && vector[13] > 0) score += 0.35;

            // Form Count
            if (vector.Length > 14 && vector[14] > 5) score += 0.1;

            // Input Field Count  
            if (vector.Length > 15 && vector[15] > 10) score += 0.15;

            // Punycode (Binary)
            if (vector.Length > 19 && vector[19] > 0) score += 0.3;

            // Vietnamese Gambling (Binary)
            if (vector.Length > 21 && vector[21] > 0) score += 0.5;

            // Vietnamese Urgency (Binary)
            if (vector.Length > 22 && vector[22] > 0) score += 0.2;

            // Vietnamese Threats Count
            if (vector.Length > 23) 
            {
                var threatCount = vector[23];
                if (threatCount > 0) score += threatCount * 0.15;
            }
        }

        // Apply context adjustments
        bool hasVietnameseContext = vector[5] > 0 || vector[6] > 0;
        if (hasVietnameseContext)
        {
            score *= 1.1; // 10% boost for Vietnamese threats
        }

        // Educational domain penalty
        bool isEducationalDomain = vector.Length > 25 && vector[25] > 0;
        if (isEducationalDomain)
        {
            score *= 0.4; // 60% reduction for educational domains
        }

        return Math.Min(1.0, score);
    }

    /// <summary>
    /// Clean old cache entries
    /// </summary>
    public void CleanCache()
    {
        var expired = _scoreCache
            .Where(kvp => DateTime.UtcNow - kvp.Value.cached > _cacheExpiry)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expired)
        {
            _scoreCache.TryRemove(key, out _);
        }

        Console.WriteLine($"🧹 Cleaned {expired.Count} expired cache entries");
    }

    public void Dispose()
    {
        _scoreCache.Clear();
    }
}