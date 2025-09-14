using System;
using System.Threading.Tasks;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PhishRadar.Core.Abstractions;
using PhishRadar.Core.Models;

namespace PhishRadar.Rules;

/// <summary>
/// Enhanced ML Scorer with REAL ONNX model integration + fallback intelligence
/// </summary>
public sealed class EnhancedMlScorer : IMlScorer
{
    private readonly InferenceSession? _onnxSession;
    private readonly Random _random = new(42);

    public EnhancedMlScorer()
    {
        try
        {
            // Load ONNX model if available
            var onnxPath = Path.Combine(AppContext.BaseDirectory, "phishradar.onnx");
            if (File.Exists(onnxPath))
            {
                var sessionOptions = new SessionOptions
                {
                    EnableCpuMemArena = false,
                    EnableMemoryPattern = false
                };
                _onnxSession = new InferenceSession(onnxPath, sessionOptions);
                Console.WriteLine("[INFO] ONNX model loaded successfully");
            }
            else
            {
                Console.WriteLine("[WARN] ONNX model not found, using intelligent fallback");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARN] Failed to load ONNX model: {ex.Message}, using fallback");
            _onnxSession = null;
        }
    }

    public Task<double> ScoreAsync(float[] vector, CancellationToken ct = default)
    {
        if (vector == null || vector.Length == 0)
            return Task.FromResult(0.0);

        double score;

        if (_onnxSession != null)
        {
            // Use REAL ONNX model
            score = ScoreWithONNX(vector);
        }
        else
        {
            // Intelligent fallback when ONNX not available
            score = ScoreWithIntelligentFallback(vector);
        }

        return Task.FromResult(Math.Max(0, Math.Min(1.0, score)));
    }

    /// <summary>
    /// Score using actual trained ONNX model
    /// </summary>
    private double ScoreWithONNX(float[] features)
    {
        try
        {
            // Ensure we have the right number of features
            var modelFeatures = new float[7]; // phishradar.onnx expects 7 features
            for (int i = 0; i < Math.Min(features.Length, 7); i++)
            {
                modelFeatures[i] = features[i];
            }

            var inputTensor = new DenseTensor<float>(modelFeatures, new[] { 1, 7 });
            var inputs = new List<NamedOnnxValue>
            {
                NamedOnnxValue.CreateFromTensor("Features", inputTensor)
            };

            using var results = _onnxSession!.Run(inputs);
            var output = results.FirstOrDefault()?.AsTensor<float>();
            
            return output?[1] ?? 0.0; // Return probability of positive class
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARN] ONNX inference failed: {ex.Message}, using fallback");
            return ScoreWithIntelligentFallback(features);
        }
    }

    /// <summary>
    /// Intelligent fallback scoring when ONNX is not available
    /// </summary>
    private double ScoreWithIntelligentFallback(float[] vector)
    {
        if (vector.Length >= 25) // Advanced feature vector
        {
            return CalculateAdvancedIntelligentScore(vector);
        }
        else // Basic feature vector
        {
            return CalculateBasicIntelligentScore(vector);
        }
    }

    /// <summary>
    /// Advanced ML scoring with explainability
    /// </summary>
    public async Task<(double score, Dictionary<string, double> featureContributions)> ScoreAdvancedWithExplainabilityAsync(AdvancedFeatures features, CancellationToken ct = default)
    {
        var vector = features.NumericalFeatures.Length > 0 
            ? features.NumericalFeatures 
            : new EnhancedFeaturizer().Vectorize(features);

        var score = await ScoreAsync(vector, ct);
        var contributions = CalculateFeatureContributions(vector, features);

        return (score, contributions);
    }

    /// <summary>
    /// Calculate feature contributions for explainability
    /// </summary>
    private Dictionary<string, double> CalculateFeatureContributions(float[] vector, AdvancedFeatures features)
    {
        var contributions = new Dictionary<string, double>();

        if (vector.Length >= 7) // Standard model features
        {
            // These correspond to the CSV training features
            contributions["UrlLength"] = CalculateContribution(vector[0], 100, 0.2);
            contributions["HasSuspiciousPattern"] = CalculateContribution(vector[1], 1, 0.3);
            contributions["HasHyphen"] = CalculateContribution(vector[2], 1, 0.25);
            contributions["NumDigits"] = CalculateContribution(vector[3], 10, 0.2);
            contributions["IsHttp"] = CalculateContribution(vector[4], 1, 0.4);
            contributions["ContainsOtpKeyword"] = CalculateContribution(vector[5], 1, 0.5);
            contributions["ContainsBankKeyword"] = CalculateContribution(vector[6], 1, 0.45);
        }

        // Advanced features contributions
        if (features.IsSuspiciousTld)
            contributions["SuspiciousTLD"] = 0.35;
        if (features.IsVietnameseBankDomain)
            contributions["VietnameseBankDomain"] = 0.3;
        if (features.HasVietnamesePhishingKeywords)
            contributions["VietnamesePhishingKeywords"] = 0.4;
        if (features.Protocol == "http")
            contributions["HttpProtocol"] = 0.25;

        return contributions.Where(x => x.Value > 0.1).ToDictionary(x => x.Key, x => x.Value);
    }

    private double CalculateContribution(float featureValue, float maxExpected, double weight)
    {
        var normalizedValue = Math.Min(1.0, featureValue / maxExpected);
        return normalizedValue * weight;
    }

    /// <summary>
    /// Score based on advanced features with smart domain recognition
    /// </summary>
    public async Task<double> ScoreAdvancedAsync(AdvancedFeatures features, CancellationToken ct = default)
    {
        var vector = features.NumericalFeatures.Length > 0 
            ? features.NumericalFeatures 
            : new EnhancedFeaturizer().Vectorize(features);
            
        var baseScore = await ScoreAsync(vector, ct);
        
        // SMART: Reduce false positives for legitimate domains
        double legitimacyAdjustment = 0.0;
        if (IsLegitimateEducationalDomain(features.Host))
        {
            legitimacyAdjustment = -0.4; // Significant reduction for educational domains
        }
        else if (IsLegitimateGovernmentDomain(features.Host))
        {
            legitimacyAdjustment = -0.3; // Reduction for government domains
        }
        else if (features.Protocol == "https" && !features.IsSuspiciousTld)
        {
            legitimacyAdjustment = -0.1; // Small bonus for HTTPS legitimate domains
        }
        
        // Additional scoring based on Vietnamese-specific threats
        double vietnameseBoost = 0.0;
        if (features.IsVietnameseBankDomain && features.IsSuspiciousTld)
            vietnameseBoost += 0.3;
            
        if (features.HasVietnamesePhishingKeywords && !IsLegitimateEducationalDomain(features.Host))
            vietnameseBoost += 0.2;
            
        if (features.VietnameseThreats.Length > 2 && !IsLegitimateEducationalDomain(features.Host))
            vietnameseBoost += 0.15;
            
        // HTTP penalty only for non-legitimate domains
        double httpPenalty = 0.0;
        if (features.Protocol == "http" && !IsLegitimateEducationalDomain(features.Host) && !IsLegitimateGovernmentDomain(features.Host))
        {
            httpPenalty = 0.2;
        }
            
        var finalScore = Math.Max(0, Math.Min(1.0, baseScore + vietnameseBoost + httpPenalty + legitimacyAdjustment));
        return finalScore;
    }

    private bool IsLegitimateEducationalDomain(string host)
    {
        return host.EndsWith(".edu.vn") || host.EndsWith(".ac.vn") || 
               host.Contains("university") || host.Contains("college") || 
               host.Contains("school") || host.Contains("huflit") ||
               host.Contains("hcmus") || host.Contains("uit") || host.Contains("hcmut");
    }

    private bool IsLegitimateGovernmentDomain(string host)
    {
        return host.EndsWith(".gov.vn") || host.EndsWith(".org.vn");
    }

    private double CalculateAdvancedIntelligentScore(float[] vector)
    {
        // Weighted scoring based on cybersecurity research
        double urlComplexity = Math.Min(1.0, vector[0] / 200.0);  // URL length factor
        double hostComplexity = Math.Min(1.0, vector[1] / 100.0); // Host length factor
        double pathComplexity = Math.Min(1.0, vector[2] / 50.0);  // Path length factor
        double subdomainRisk = Math.Min(1.0, vector[3] / 5.0);    // Subdomain count
        double hyphenRisk = Math.Min(1.0, vector[4] / 3.0);       // Hyphen count
        double digitRisk = Math.Min(1.0, vector[5] / 10.0);       // Digit count
        double entropyRisk = vector.Length > 7 ? Math.Min(1.0, vector[7] / 5.0) : 0;
        
        // Content-based risks
        double formRisk = vector.Length > 12 ? Math.Min(1.0, vector[12] / 10.0) : 0;
        double inputRisk = vector.Length > 13 ? Math.Min(1.0, vector[13] / 20.0) : 0;
        
        // Binary flags (0 or 1)
        double suspiciousTld = vector.Length > 15 ? vector[15] * 0.4 : 0;
        double punycode = vector.Length > 16 ? vector[16] * 0.3 : 0;
        double vietnameseBank = vector.Length > 17 ? vector[17] * 0.5 : 0;
        double vietnameseKeywords = vector.Length > 18 ? vector[18] * 0.3 : 0;
        double sensitiveFields = vector.Length > 19 ? vector[19] * 0.25 : 0;
        double urgentLanguage = vector.Length > 20 ? vector[20] * 0.2 : 0;
        
        // Educational domain bonus (reduce false positives)
        double educationalBonus = vector.Length > 26 && vector[26] == 1 ? -0.3 : 0;
        
        // Weighted combination
        double structuralScore = 0.15 * urlComplexity + 0.20 * hostComplexity + 
                               0.10 * pathComplexity + 0.15 * subdomainRisk + 
                               0.10 * hyphenRisk + 0.05 * digitRisk + 0.10 * entropyRisk;
                               
        double contentScore = 0.15 * formRisk + 0.20 * inputRisk;
        
        double flagScore = suspiciousTld + punycode + vietnameseBank + 
                          vietnameseKeywords + sensitiveFields + urgentLanguage;
        
        return Math.Max(0, Math.Min(1.0, 
            0.3 * structuralScore + 0.3 * contentScore + 0.4 * flagScore + educationalBonus));
    }

    private double CalculateBasicIntelligentScore(float[] vector)
    {
        // Simple scoring for basic vectors
        double urlComplexity = Math.Min(1.0, vector[0] / 100.0);  // URL length factor
        double suspiciousPatterns = vector.Length > 1 ? Math.Min(1.0, vector[1] / 50.0) : 0;
        double contentLength = vector.Length > 2 ? Math.Min(1.0, vector[2] / 1000.0) : 0;
        
        // Enhanced features if available
        double hyphenRisk = vector.Length > 3 ? Math.Min(1.0, vector[3] / 3.0) : 0;
        double digitRisk = vector.Length > 4 ? Math.Min(1.0, vector[4] / 10.0) : 0;
        double punycodeRisk = vector.Length > 5 ? vector[5] * 0.3 : 0;
        double pathRisk = vector.Length > 6 ? vector[6] * 0.2 : 0;
        double otpRisk = vector.Length > 7 ? vector[7] * 0.25 : 0;

        return Math.Min(1.0, 0.2 * urlComplexity + 0.2 * suspiciousPatterns + 
                            0.1 * contentLength + 0.15 * hyphenRisk + 
                            0.1 * digitRisk + punycodeRisk + pathRisk + otpRisk);
    }

    public void Dispose()
    {
        _onnxSession?.Dispose();
    }
}