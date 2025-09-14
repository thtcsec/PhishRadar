using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PhishRadar.Core.Abstractions;
using PhishRadar.Core.Models;

namespace PhishRadar.Rules;

/// <summary>
/// Real ONNX-powered ML Scorer using trained models
/// Provides true AI inference capabilities
/// </summary>
public sealed class OnnxMlScorer : IMlScorer, IDisposable
{
    private readonly InferenceSession _session;
    private readonly ConcurrentDictionary<string, float> _featureCache = new();
    private static readonly SessionOptions SessionOptions = new()
    {
        InterOpNumThreads = 1,
        IntraOpNumThreads = 1,
        ExecutionMode = ExecutionMode.ORT_SEQUENTIAL
    };

    public OnnxMlScorer(string modelPath = "phishradar.onnx")
    {
        try
        {
            // Try to load from multiple possible locations
            var possiblePaths = new[]
            {
                modelPath,
                Path.Combine(AppContext.BaseDirectory, modelPath),
                Path.Combine(AppContext.BaseDirectory, "Models", modelPath),
                Path.Combine(Directory.GetCurrentDirectory(), modelPath)
            };

            string? actualPath = null;
            foreach (var path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    actualPath = path;
                    break;
                }
            }

            if (actualPath == null)
            {
                throw new FileNotFoundException($"ONNX model not found in any of the expected locations: {string.Join(", ", possiblePaths)}");
            }

            _session = new InferenceSession(actualPath, SessionOptions);
            Console.WriteLine($"[AI] Loaded ONNX model from: {actualPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to load ONNX model: {ex.Message}");
            throw new InvalidOperationException("Failed to initialize ONNX ML model", ex);
        }
    }

    public async Task<double> ScoreAsync(float[] vector, CancellationToken ct = default)
    {
        if (vector == null || vector.Length == 0)
            return 0.0;

        try
        {
            // Ensure we have the expected 7 features for the trained model
            var normalizedVector = NormalizeFeatureVector(vector);
            var cacheKey = string.Join(",", normalizedVector.Select(f => f.ToString("F3")));
            
            if (_featureCache.TryGetValue(cacheKey, out var cachedScore))
                return cachedScore;

            // Create ONNX tensor
            var inputTensor = new DenseTensor<float>(normalizedVector, new[] { 1, normalizedVector.Length });
            var inputs = new List<NamedOnnxValue>
            {
                NamedOnnxValue.CreateFromTensor("Features", inputTensor)
            };

            // Run inference
            using var results = _session.Run(inputs);
            var scoreOutput = results.FirstOrDefault()?.AsEnumerable<float>().FirstOrDefault() ?? 0f;
            
            // Clamp to valid probability range
            var finalScore = Math.Max(0, Math.Min(1.0, scoreOutput));
            
            // Cache result
            _featureCache.TryAdd(cacheKey, (float)finalScore);
            
            return finalScore;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[AI ERROR] ONNX inference failed: {ex.Message}");
            // Fallback to enhanced scoring
            return await FallbackScoring(vector);
        }
    }

    private float[] NormalizeFeatureVector(float[] vector)
    {
        // Ensure we have exactly 7 features as expected by the trained model
        var normalized = new float[7];
        
        if (vector.Length >= 7)
        {
            // Use first 7 features directly
            Array.Copy(vector, normalized, 7);
        }
        else
        {
            // Pad with zeros or derive from available features
            Array.Copy(vector, normalized, vector.Length);
            
            // Smart feature derivation for missing features
            if (vector.Length >= 3)
            {
                // Derive additional features from basic ones
                for (int i = vector.Length; i < 7; i++)
                {
                    normalized[i] = i switch
                    {
                        3 => vector[0] > 50 ? 1f : 0f, // HasHyphen from UrlLength
                        4 => vector[0] > 30 ? vector[0] / 100f : 0f, // NumDigits estimate
                        5 => vector.Length > 6 && vector[6] > 0 ? 1f : 0f, // IsHttp
                        6 => vector.Length > 7 && vector[7] > 0 ? 1f : 0f, // ContainsOtpKeyword
                        _ => 0f
                    };
                }
            }
        }

        // Apply normalization to prevent extreme values
        for (int i = 0; i < normalized.Length; i++)
        {
            normalized[i] = i switch
            {
                0 => Math.Min(normalized[i] / 200f, 1f), // UrlLength normalization
                1 => Math.Min(normalized[i], 1f),        // HasAt (already binary)
                2 => Math.Min(normalized[i], 1f),        // HasHyphen (binary)
                3 => Math.Min(normalized[i] / 20f, 1f),  // NumDigits normalization
                4 => Math.Min(normalized[i], 1f),        // IsHttp (binary)
                5 => Math.Min(normalized[i], 1f),        // ContainsOtpKeyword (binary)
                6 => Math.Min(normalized[i], 1f),        // ContainsBankKeyword (binary)
                _ => normalized[i]
            };
        }

        return normalized;
    }

    private async Task<double> FallbackScoring(float[] vector)
    {
        // Enhanced heuristic scoring when ONNX fails
        double score = 0.0;
        
        if (vector.Length > 0) score += Math.Min(vector[0] / 200.0, 0.3);  // URL length
        if (vector.Length > 1) score += vector[1] * 0.2;                   // HasAt
        if (vector.Length > 2) score += vector[2] * 0.15;                  // HasHyphen
        if (vector.Length > 3) score += Math.Min(vector[3] / 10.0, 0.15);  // NumDigits
        if (vector.Length > 4) score += vector[4] * 0.1;                   // IsHttp
        if (vector.Length > 5) score += vector[5] * 0.25;                  // OTP keywords
        if (vector.Length > 6) score += vector[6] * 0.2;                   // Bank keywords

        return Math.Min(1.0, score);
    }

    public void Dispose()
    {
        _session?.Dispose();
        _featureCache.Clear();
    }
}