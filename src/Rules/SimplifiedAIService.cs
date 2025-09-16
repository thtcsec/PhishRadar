using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PhishRadar.Core.Abstractions;
using PhishRadar.Core.Models;
using System.Collections.Concurrent;

namespace PhishRadar.Rules;

/// <summary>
/// Enterprise-grade AI Service with sophisticated threat detection
/// </summary>
public sealed class SimplifiedAIService : IMlScorer, IDisposable
{
    private readonly Random _random = new(42);
    
    // Performance caching
    private readonly ConcurrentDictionary<string, (double score, DateTime cached)> _scoreCache = new();
    private readonly TimeSpan _cacheExpiry = TimeSpan.FromMinutes(5);

    public SimplifiedAIService()
    {
        Console.WriteLine("🤖 Enterprise AI Service initialized with sophisticated detection");
    }

    public Task<double> ScoreAsync(float[] vector, CancellationToken ct = default)
    {
        if (vector == null || vector.Length == 0)
            return Task.FromResult(0.0);

        // Check cache first
        var cacheKey = string.Join(",", vector.Take(10)); // Use first 10 features for caching
        if (_scoreCache.TryGetValue(cacheKey, out var cached) && 
            DateTime.UtcNow - cached.cached < _cacheExpiry)
        {
            return Task.FromResult(cached.score);
        }

        // Sophisticated scoring algorithm
        var score = CalculateSophisticatedScore(vector);

        // Cache the result
        _scoreCache.TryAdd(cacheKey, (score, DateTime.UtcNow));

        return Task.FromResult(Math.Max(0, Math.Min(1.0, score)));
    }

    /// <summary>
    /// Advanced scoring with explainability for sophisticated models
    /// </summary>
    public Task<(double score, Dictionary<string, double> featureContributions)> ScoreAdvancedWithExplainabilityAsync(
        AdvancedFeatures features, CancellationToken ct = default)
    {
        var vector = features.NumericalFeatures.Length > 0 
            ? features.NumericalFeatures 
            : new EnhancedFeaturizer().Vectorize(features);

        var score = CalculateSophisticatedScore(vector);
        var contributions = CalculateSophisticatedContributions(vector, features);

        return Task.FromResult((score, contributions));
    }

    private Dictionary<string, double> CalculateSophisticatedContributions(float[] vector, AdvancedFeatures features)
    {
        var contributions = new Dictionary<string, double>();

        if (vector.Length >= 30) // Sophisticated 30-feature model
        {
            // Critical security indicators
            if (vector[4] > 0) contributions["HTTP_Protocol"] = 0.35; // IsHttp
            if (vector[13] > 0) contributions["Punycode_Attack"] = 0.40; // HasPunycode
            if (vector[12] > 0) contributions["Suspicious_TLD"] = 0.32; // HasSuspiciousTld
            
            // Domain intelligence
            if (vector[11] < 30) contributions["Young_Domain"] = 0.45; // DomainAge < 30 days
            if (vector[19] < 0.5) contributions["Poor_IP_Reputation"] = 0.38; // IPReputation
            if (vector[21] < 0.3) contributions["Bad_ASN_Reputation"] = 0.35; // ASNReputation
            
            // Banking similarity (critical for Vietnamese context)
            if (vector[18] > 0.7) contributions["Bank_Impersonation"] = 0.50; // SimilarityToKnownBank
            
            // Content-based threats
            if (vector[16] > 3) contributions["Sensitive_Input_Fields"] = 0.42; // SensitiveInputs
            if (vector[17] > 0) contributions["Urgency_Language"] = 0.28; // HasUrgencyText
            if (vector[24] > 0) contributions["JavaScript_Obfuscation"] = 0.33; // JSObfuscated
            if (vector[25] > 0) contributions["Hidden_Iframes"] = 0.30; // HiddenIframes
            
            // Vietnamese-specific threats
            if (vector[27] > 0) contributions["Vietnamese_Phishing_Text"] = 0.45; // TextVietnamesePhishing
            if (vector[6] > 0) contributions["Banking_Keywords"] = 0.40; // ContainsBankKeyword
            if (vector[5] > 0) contributions["OTP_Keywords"] = 0.38; // ContainsOtpKeyword
            
            // Advanced similarity analysis
            if (vector[26] > 0.7) contributions["Favicon_Cloning"] = 0.32; // FaviconSimilarity
            if (vector[28] > 0.7) contributions["Content_Similarity"] = 0.35; // ContentSimilarity
            
            // Technical indicators
            if (vector[23] > 1) contributions["Multiple_Redirects"] = 0.25; // RedirectCount
            if (vector[29] > 0) contributions["Meta_Refresh_Redirect"] = 0.22; // MetaRefreshRedirect
            
            // Structural complexity
            if (vector[1] > 150) contributions["Excessive_URL_Length"] = 0.20; // UrlLength
            if (vector[10] > 4) contributions["Deep_Subdomain_Structure"] = 0.28; // SubdomainCount
        }

        // Enhanced legacy support
        if (vector.Length >= 7)
        {
            if (vector[4] > 0) contributions["HTTP_Protocol"] = 0.35;
            if (vector[5] > 0) contributions["OTP_Keywords"] = 0.40;
            if (vector[6] > 0) contributions["Banking_Keywords"] = 0.45;
        }

        // Return only significant contributions (top 8)
        return contributions
            .Where(x => x.Value > 0.15)
            .OrderByDescending(x => x.Value)
            .Take(8)
            .ToDictionary(x => x.Key, x => x.Value);
    }

    private double CalculateSophisticatedScore(float[] vector)
    {
        if (vector.Length < 7) return 0;

        double score = 0;

        // === CONTEXT-AWARE ANALYSIS ===
        
        // Educational domain protection (strongest override)
        bool isEducational = vector.Length > 30 && vector[30] > 0; // IsEducational feature
        bool isLegitimateReference = vector.Length > 34 && vector[34] > 0; // IsLegitimateReference feature
        
        if (isEducational || isLegitimateReference)
        {
            // For educational/reference sites, massively reduce risk
            score *= 0.1; // 90% reduction
            return Math.Max(0, Math.Min(0.3, score)); // Cap at 30% max
        }

        // === CRITICAL THREAT INDICATORS (High Weight) ===
        
        // 1. Protocol Security (35% weight)
        if (vector.Length > 4 && vector[4] > 0) // IsHttp
            score += 0.35;

        // 2. Domain Intelligence (High Weight)
        if (vector.Length > 11 && vector[11] < 7) // DomainAge < 7 days
            score += 0.45;
        else if (vector.Length > 11 && vector[11] < 30) // DomainAge < 30 days
            score += 0.25;

        if (vector.Length > 13 && vector[13] > 0) // HasPunycode
            score += 0.40;

        if (vector.Length > 12 && vector[12] > 0) // HasSuspiciousTld
            score += 0.32;

        // 3. Bank Impersonation (Critical for Vietnamese market) - CONTEXT-AWARE
        if (vector.Length > 18 && vector[18] > 0.8) // SimilarityToKnownBank
        {
            bool hostContainsBank = vector.Length > 33 && vector[33] > 0;
            if (hostContainsBank && !isEducational)
                score += 0.50; // Only flag if actually contains bank name AND not educational
        }

        // 4. IP & ASN Reputation
        if (vector.Length > 19 && vector[19] < 0.3) // Poor IP reputation
            score += 0.38;
        if (vector.Length > 21 && vector[21] < 0.2) // Bad ASN reputation
            score += 0.35;

        // === CONTENT-BASED THREATS (Medium-High Weight) ===

        // 5. Sensitive Data Harvesting
        if (vector.Length > 16 && vector[16] > 5) // Many sensitive inputs
            score += 0.42;
        else if (vector.Length > 16 && vector[16] > 2)
            score += 0.25;

        // 6. Vietnamese Phishing Patterns - CONTEXT-AWARE
        if (vector.Length > 27 && vector[27] > 0) // Vietnamese phishing text
        {
            if (!isEducational && !isLegitimateReference)
                score += 0.45;
        }

        // 7. Gambling Detection - CONTEXT-AWARE
        bool hasGamblingContext = vector.Length > 31 && vector[31] > 0;
        bool pathContainsGambling = vector.Length > 32 && vector[32] > 0;
        
        if (hasGamblingContext || pathContainsGambling)
        {
            if (!isEducational && !isLegitimateReference)
                score += 0.50; // High penalty for actual gambling
        }

        if (vector.Length > 5 && vector[5] > 0) // OTP keywords
        {
            if (!isEducational)
                score += 0.38;
        }

        if (vector.Length > 6 && vector[6] > 0) // Banking keywords
        {
            if (!isEducational && !isLegitimateReference)
                score += 0.40;
        }

        // 8. Advanced Obfuscation
        if (vector.Length > 24 && vector[24] > 0) // JS obfuscation
            score += 0.33;

        if (vector.Length > 25 && vector[25] > 1) // Hidden iframes
            score += 0.30;

        // === BEHAVIORAL INDICATORS (Medium Weight) ===

        // 9. Urgency Tactics
        if (vector.Length > 17 && vector[17] > 0) // Urgency language
        {
            if (!isEducational)
                score += 0.28;
        }

        // 10. Visual Deception
        if (vector.Length > 26 && vector[26] > 0.7) // Favicon similarity
            score += 0.32;

        if (vector.Length > 28 && vector[28] > 0.7) // Content similarity
            score += 0.35;

        // 11. Technical Redirects
        if (vector.Length > 23 && vector[23] > 2) // Multiple redirects
            score += 0.25;

        if (vector.Length > 29 && vector[29] > 0) // Meta refresh
            score += 0.22;

        // === STRUCTURAL COMPLEXITY (Lower Weight) ===

        // 12. URL Structure Analysis
        if (vector.Length > 1 && vector[1] > 150) // Long URL
            score += 0.20;

        if (vector.Length > 10 && vector[10] > 5) // Too many subdomains
            score += 0.28;
        else if (vector.Length > 10 && vector[10] > 3)
            score += 0.15;

        if (vector.Length > 2 && vector[2] > 5) // Many hyphens
            score += 0.18;

        if (vector.Length > 3 && vector[3] > 10) // Many digits
            score += 0.15;

        // === TEMPORAL FACTORS ===
        if (vector.Length > 22 && vector[22] < 30) // Young SSL cert
            score += 0.15;

        // === CONTEXT ADJUSTMENTS ===

        // Vietnamese context boost (only for non-educational)
        bool hasVietnameseContext = (vector.Length > 27 && vector[27] > 0) || 
                                   (vector.Length > 6 && vector[6] > 0);
        if (hasVietnameseContext && !isEducational)
            score *= 1.1; // 10% boost for Vietnamese threats

        // Multiple threat indicators = higher confidence
        int threatCount = 0;
        if (vector.Length > 4 && vector[4] > 0) threatCount++; // HTTP
        if (vector.Length > 13 && vector[13] > 0) threatCount++; // Punycode
        if (vector.Length > 18 && vector[18] > 0.5) threatCount++; // Bank similarity
        if (vector.Length > 27 && vector[27] > 0 && !isEducational) threatCount++; // VN phishing
        if (vector.Length > 24 && vector[24] > 0) threatCount++; // JS obfuscation

        if (threatCount > 2 && !isEducational)
            score *= 1.15; // 15% boost for multiple indicators

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

        Console.WriteLine($"🧹 Cleaned {expired.Count} expired cache entries from sophisticated AI");
    }

    public void Dispose()
    {
        _scoreCache.Clear();
    }
}