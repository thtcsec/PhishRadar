using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PhishRadar.Core.Abstractions;
using PhishRadar.Core.Models;
using System.Collections.Concurrent;

namespace PhishRadar.Rules;

/// <summary>
/// Production-Ready AI Service with multiple models and intelligent fallback
/// </summary>
public sealed class ProductionAIService : IMlScorer, IDisposable
{
    private readonly InferenceSession? _primaryModel;
    private readonly InferenceSession? _lightGbmModel;
    private readonly InferenceSession? _fastTreeModel;
    private readonly InferenceSession? _logisticModel;
    private readonly Random _random = new(42);
    
    // Performance caching
    private readonly ConcurrentDictionary<string, (double score, DateTime cached)> _scoreCache = new();
    private readonly TimeSpan _cacheExpiry = TimeSpan.FromMinutes(5);

    public ProductionAIService()
    {
        var modelsPath = Path.Combine(AppContext.BaseDirectory, "models");
        Directory.CreateDirectory(modelsPath);

        _primaryModel = LoadModel(Path.Combine(modelsPath, "phishradar.onnx"), "Primary Ensemble");
        _lightGbmModel = LoadModel(Path.Combine(modelsPath, "phishradar_lightgbm.onnx"), "LightGBM");
        _fastTreeModel = LoadModel(Path.Combine(modelsPath, "phishradar_fasttree.onnx"), "FastTree");
        _logisticModel = LoadModel(Path.Combine(modelsPath, "phishradar_logistic.onnx"), "Logistic");

        Console.WriteLine($"🤖 AI Service initialized with {GetLoadedModelsCount()} models");
    }

    private InferenceSession? LoadModel(string modelPath, string modelName)
    {
        try
        {
            if (!File.Exists(modelPath))
            {
                // Try alternative locations
                var altPath = Path.Combine(AppContext.BaseDirectory, Path.GetFileName(modelPath));
                if (File.Exists(altPath))
                {
                    modelPath = altPath;
                }
                else
                {
                    Console.WriteLine($"⚠️ {modelName} model not found at {modelPath}");
                    return null;
                }
            }

            var sessionOptions = new SessionOptions
            {
                EnableCpuMemArena = false,
                EnableMemoryPattern = false,
                ExecutionMode = ExecutionMode.ORT_SEQUENTIAL,
                GraphOptimizationLevel = GraphOptimizationLevel.ORT_ENABLE_ALL
            };

            var session = new InferenceSession(modelPath, sessionOptions);
            Console.WriteLine($"✅ {modelName} model loaded successfully");
            return session;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Failed to load {modelName} model: {ex.Message}");
            return null;
        }
    }

    private int GetLoadedModelsCount()
    {
        int count = 0;
        if (_primaryModel != null) count++;
        if (_lightGbmModel != null) count++;
        if (_fastTreeModel != null) count++;
        if (_logisticModel != null) count++;
        return count;
    }

    public async Task<double> ScoreAsync(float[] vector, CancellationToken ct = default)
    {
        if (vector == null || vector.Length == 0)
            return 0.0;

        // Check cache first
        var cacheKey = string.Join(",", vector.Take(7)); // Use first 7 features for caching
        if (_scoreCache.TryGetValue(cacheKey, out var cached) && 
            DateTime.UtcNow - cached.cached < _cacheExpiry)
        {
            return cached.score;
        }

        double finalScore;

        if (GetLoadedModelsCount() == 0)
        {
            // Pure fallback when no models available
            finalScore = CalculateIntelligentFallbackScore(vector);
        }
        else
        {
            // AI Ensemble scoring with multiple models
            finalScore = await CalculateEnsembleScore(vector, ct);
        }

        // Cache the result
        _scoreCache.TryAdd(cacheKey, (finalScore, DateTime.UtcNow));

        return Math.Max(0, Math.Min(1.0, finalScore));
    }

    private async Task<double> CalculateEnsembleScore(float[] vector, CancellationToken ct)
    {
        var scores = new List<(double score, double weight, string model)>();

        // Try primary model first (highest weight)
        if (_primaryModel != null)
        {
            var primaryScore = await RunInferenceAsync(_primaryModel, vector, "Primary");
            if (primaryScore.HasValue)
                scores.Add((primaryScore.Value, 0.4, "Primary"));
        }

        // Try LightGBM model (second highest weight)
        if (_lightGbmModel != null)
        {
            var lgbScore = await RunInferenceAsync(_lightGbmModel, vector, "LightGBM");
            if (lgbScore.HasValue)
                scores.Add((lgbScore.Value, 0.3, "LightGBM"));
        }

        // Try FastTree model
        if (_fastTreeModel != null)
        {
            var ftScore = await RunInferenceAsync(_fastTreeModel, vector, "FastTree");
            if (ftScore.HasValue)
                scores.Add((ftScore.Value, 0.2, "FastTree"));
        }

        // Try Logistic model
        if (_logisticModel != null)
        {
            var logScore = await RunInferenceAsync(_logisticModel, vector, "Logistic");
            if (logScore.HasValue)
                scores.Add((logScore.Value, 0.1, "Logistic"));
        }

        if (scores.Count == 0)
        {
            // All models failed, use intelligent fallback
            return CalculateIntelligentFallbackScore(vector);
        }

        // Weighted ensemble scoring
        var totalWeight = scores.Sum(s => s.weight);
        var weightedScore = scores.Sum(s => s.score * s.weight) / totalWeight;

        // Apply confidence adjustment based on model agreement
        var variance = CalculateVariance(scores.Select(s => s.score));
        var confidenceAdjustment = variance > 0.1 ? 0.9 : 1.0; // Reduce confidence if models disagree

        return weightedScore * confidenceAdjustment;
    }

    private async Task<double?> RunInferenceAsync(InferenceSession session, float[] features, string modelName)
    {
        try
        {
            // Ensure we have the right number of features for the model
            var modelFeatures = new float[7]; // Standard 7 features
            for (int i = 0; i < Math.Min(features.Length, 7); i++)
            {
                modelFeatures[i] = features[i];
            }

            var inputTensor = new DenseTensor<float>(modelFeatures, new[] { 1, 7 });
            var inputs = new List<NamedOnnxValue>
            {
                NamedOnnxValue.CreateFromTensor("Features", inputTensor)
            };

            using var results = session.Run(inputs);
            var output = results.FirstOrDefault()?.AsTensor<float>();
            
            // Handle different output formats
            if (output != null)
            {
                // For binary classification, get probability of positive class
                return output.Length > 1 ? output[1] : output[0];
            }

            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠️ {modelName} inference failed: {ex.Message}");
            return null;
        }
    }

    private double CalculateVariance(IEnumerable<double> scores)
    {
        var scoreList = scores.ToList();
        if (scoreList.Count <= 1) return 0;

        var mean = scoreList.Average();
        var variance = scoreList.Sum(score => Math.Pow(score - mean, 2)) / scoreList.Count;
        return variance;
    }

    /// <summary>
    /// Advanced scoring with explainability for enhanced models
    /// </summary>
    public async Task<(double score, Dictionary<string, double> featureContributions)> ScoreAdvancedWithExplainabilityAsync(
        AdvancedFeatures features, CancellationToken ct = default)
    {
        var vector = features.NumericalFeatures.Length > 0 
            ? features.NumericalFeatures 
            : new EnhancedFeaturizer().Vectorize(features);

        var score = await ScoreAsync(vector, ct);
        var contributions = CalculateFeatureContributions(vector, features);

        return (score, contributions);
    }

    private Dictionary<string, double> CalculateFeatureContributions(float[] vector, AdvancedFeatures features)
    {
        var contributions = new Dictionary<string, double>();

        if (vector.Length >= 7)
        {
            // Standard model features with SHAP-like contributions
            contributions["URL_Length"] = NormalizeContribution(vector[0], 150, 0.15);
            contributions["Has_At_Symbol"] = vector[1] * 0.25;
            contributions["Hyphen_Count"] = NormalizeContribution(vector[2], 5, 0.20);
            contributions["Digit_Count"] = NormalizeContribution(vector[3], 15, 0.18);
            contributions["HTTP_Protocol"] = vector[4] * 0.35;
            contributions["OTP_Keywords"] = vector[5] * 0.40;
            contributions["Banking_Keywords"] = vector[6] * 0.45;
        }

        // Advanced feature contributions
        if (features.IsSuspiciousTld)
            contributions["Suspicious_TLD"] = 0.35;
        if (features.IsVietnameseBankDomain)
            contributions["Vietnamese_Banking"] = 0.30;
        if (features.HasVietnamesePhishingKeywords)
            contributions["Vietnamese_Phishing"] = 0.40;
        if (features.Protocol == "http")
            contributions["Insecure_Protocol"] = 0.25;

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

    private double CalculateIntelligentFallbackScore(float[] vector)
    {
        if (vector.Length < 7) return 0;

        // Enhanced heuristic scoring based on cybersecurity research
        double urlScore = Math.Min(1.0, vector[0] / 100.0) * 0.15;      // URL length
        double atScore = vector[1] * 0.25;                               // @ symbol
        double hyphenScore = Math.Min(1.0, vector[2] / 3.0) * 0.20;     // Hyphens
        double digitScore = Math.Min(1.0, vector[3] / 10.0) * 0.18;     // Digits
        double httpScore = vector[4] * 0.35;                             // HTTP
        double otpScore = vector[5] * 0.40;                              // OTP keywords
        double bankScore = vector[6] * 0.45;                             // Banking keywords

        // Advanced features if available
        double advancedScore = 0;
        if (vector.Length > 7)
        {
            var hostLength = vector.Length > 7 ? Math.Min(1.0, vector[7] / 50.0) * 0.10 : 0;
            var pathLength = vector.Length > 8 ? Math.Min(1.0, vector[8] / 30.0) * 0.08 : 0;
            var subdomains = vector.Length > 9 ? Math.Min(1.0, vector[9] / 4.0) * 0.12 : 0;
            
            advancedScore = hostLength + pathLength + subdomains;
        }

        var totalScore = urlScore + atScore + hyphenScore + digitScore + 
                        httpScore + otpScore + bankScore + advancedScore;

        // Apply Vietnamese context boost
        if (vector.Length > 15 && vector[15] > 0) // Vietnamese context
        {
            totalScore *= 1.2; // 20% boost for Vietnamese threats
        }

        // Apply educational domain penalty
        if (vector.Length > 20 && vector[20] > 0) // Educational domain
        {
            totalScore *= 0.6; // 40% reduction for educational domains
        }

        return Math.Min(1.0, totalScore);
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
    }

    public void Dispose()
    {
        _primaryModel?.Dispose();
        _lightGbmModel?.Dispose();
        _fastTreeModel?.Dispose();
        _logisticModel?.Dispose();
        _scoreCache.Clear();
    }
}