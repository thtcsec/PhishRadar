using PhishRadar.Core.Abstractions;
using PhishRadar.Core.Models;

namespace PhishRadar.Rules;

/// <summary>
/// Enhanced featurizer that can work with both basic and advanced features
/// Now powered with AI feature engineering
/// </summary>
public sealed class EnhancedFeaturizer : IFeaturizer
{
    public float[] Vectorize((string Host, string Path, string? Text) f)
    {
        // Legacy method - enhanced with more features
        var host = f.Host ?? "";
        var path = f.Path ?? "";
        var text = f.Text ?? "";
        
        // Add AI-enhanced features
        var entropy = AIFeatureEngineer.CalculateEntropy(host);
        var (textScore, detectedPhrases) = NeuralTextAnalyzer.AnalyzeWithAttention(text);
        var (urgencyScore, trustScore) = NeuralTextAnalyzer.AnalyzeSentiment(text);
        
        return new float[] { 
            host.Length,
            path.Length, 
            text.Length,
            host.Count(c => c == '-'),
            host.Count(char.IsDigit),
            host.Contains("xn--") ? 1 : 0,
            path.Contains("login") || path.Contains("verify") ? 1 : 0,
            text.ToLowerInvariant().Contains("otp") ? 1 : 0,
            // AI-enhanced features
            (float)entropy,
            (float)textScore,
            (float)urgencyScore,
            (float)trustScore,
            detectedPhrases.Length
        };
    }
    
    public float[] Vectorize(AdvancedFeatures features) => new float[]
    {
        features.UrlLength,
        features.HostLength,
        features.PathLength,
        features.SubdomainCount,
        features.HyphenCount,
        features.DigitCount,
        features.SpecialCharCount,
        (float)features.EntropyScore,
        features.DomainAge,
        features.IsNewlyRegistered ? 1 : 0,
        features.IsSuspiciousTld ? 1 : 0,
        features.HasPunycode ? 1 : 0,
        features.FormCount,
        features.InputFieldCount,
        features.ExternalLinkCount,
        features.ImageCount,
        features.ScriptCount,
        features.HasHttpsRedirect ? 1 : 0,
        features.HasSecurityHeaders ? 1 : 0,
        features.HasValidCertificate ? 1 : 0,
        features.HasSensitiveFields ? 1 : 0,
        features.HasUrgencyLanguage ? 1 : 0,
        features.IsVietnameseBankDomain ? 1 : 0,
        features.HasVietnamesePhishingKeywords ? 1 : 0,
        features.RedirectCount,
        features.SuspiciousKeywords.Length,
        features.DetectedBrands.Length,
        features.VietnameseThreats.Length,
        features.IpAddresses.Length,
        features.RedirectChain.Length
    };

    /// <summary>
    /// Vectorize advanced features for ML processing with AI enhancement
    /// </summary>
    public float[] VectorizeAdvanced(AdvancedFeatures features)
    {
        if (features.NumericalFeatures.Length > 0)
        {
            return features.NumericalFeatures;
        }
        
        // Use AI-enhanced feature engineering
        return AIFeatureEngineer.CreateAIFeatureVector(features);
    }
    
    /// <summary>
    /// Create neural network-compatible feature vector
    /// </summary>
    public float[] VectorizeForNeuralNetwork(AdvancedFeatures features)
    {
        var (textScore, detectedPhrases) = NeuralTextAnalyzer.AnalyzeWithAttention(features.ContentText);
        var (urgencyScore, trustScore) = NeuralTextAnalyzer.AnalyzeSentiment(features.ContentText);
        var (hasPhishingPattern, patterns) = NeuralTextAnalyzer.DetectAdvancedPatterns(features.ContentText);
        
        var baseVector = Vectorize(features);
        
        // Append neural features
        var neuralFeatures = new float[]
        {
            (float)textScore,
            (float)urgencyScore,
            (float)trustScore,
            hasPhishingPattern ? 1f : 0f,
            patterns.Length,
            detectedPhrases.Length
        };
        
        return baseVector.Concat(neuralFeatures).ToArray();
    }
}