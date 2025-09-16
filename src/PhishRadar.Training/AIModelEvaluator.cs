using System.Diagnostics;
using PhishRadar.Core.Models;

namespace PhishRadar.Training;

/// <summary>
/// Simplified AI Model Evaluation Tool
/// </summary>
public class AIModelEvaluator
{
    public static async Task RunEvaluationAsync()
    {
        Console.WriteLine("🔬 PhishRadar AI Model Evaluation");
        Console.WriteLine("=================================");
        
        // Test URLs for evaluation
        var testUrls = new[]
        {
            // Legitimate sites
            ("https://huflit.edu.vn", false),
            ("https://google.com", false),
            ("https://vietcombank.com.vn", false),
            ("https://github.com", false),
            
            // Phishing sites (simulated)
            ("http://vietcom-bank.xyz/otp-verify", true),
            ("https://techcombank-update.club/login", true),
            ("http://bidv-secure.tk/urgent-verify", true),
            ("https://fake-momo.ml/payment", true),
            ("http://nohu-vip.club/casino", true),
            ("https://crypto-invest.top/bitcoin-profit", true)
        };

        Console.WriteLine($"📊 Testing {testUrls.Length} URLs with feature extraction...\n");

        await EvaluateFeatureExtraction(testUrls);
        await BenchmarkPerformance(testUrls.Take(3).ToArray());
    }

    private static async Task EvaluateFeatureExtraction((string url, bool isPhishing)[] testUrls)
    {
        Console.WriteLine("🔍 Feature Extraction Evaluation");
        Console.WriteLine("".PadRight(50, '-'));

        foreach (var (url, isPhishing) in testUrls)
        {
            var features = AIFeatureExtractor.ExtractAdvancedFeatures(url);
            var vector = features.ToArray();
            
            // Simple heuristic scoring for demonstration
            var score = CalculateHeuristicScore(features);
            var risk = (int)(score * 100);
            
            var prediction = score > 0.5;
            var isCorrect = prediction == isPhishing;
            var status = isCorrect ? "✅" : "❌";
            
            Console.WriteLine($"{status} {url.PadRight(35)} | Risk: {risk:D2}% | Features: {vector.Length}");
            Console.WriteLine($"   Key features: URLLen={features.UrlLength}, HTTP={features.IsHttp}, OTP={features.ContainsOtpKeyword}");
        }
        Console.WriteLine();
    }

    private static double CalculateHeuristicScore(AdvancedUrlFeatures features)
    {
        double score = 0;
        
        // URL length factor
        if (features.UrlLength > 80) score += 0.2;
        if (features.UrlLength > 120) score += 0.1;
        
        // Protocol factor
        if (features.IsHttp == 1) score += 0.3;
        
        // Keywords
        if (features.ContainsOtpKeyword == 1) score += 0.3;
        if (features.ContainsBankKeyword == 1) score += 0.2;
        
        // Suspicious TLD
        if (features.HasSuspiciousTld == 1) score += 0.4;
        
        // Punycode
        if (features.HasPunycode == 1) score += 0.3;
        
        // Vietnamese gambling
        if (features.HasVietnameseGamblingKeywords == 1) score += 0.5;
        
        // Educational domain (reduce score)
        if (features.IsEducationalDomain == 1) score *= 0.3;
        
        return Math.Min(1.0, score);
    }

    private static async Task BenchmarkPerformance((string url, bool isPhishing)[] testUrls)
    {
        Console.WriteLine("⚡ Performance Benchmark");
        Console.WriteLine("".PadRight(30, '-'));

        var sw = Stopwatch.StartNew();
        var iterations = 1000;

        for (int i = 0; i < iterations; i++)
        {
            foreach (var (url, _) in testUrls)
            {
                var features = AIFeatureExtractor.ExtractAdvancedFeatures(url);
                var score = CalculateHeuristicScore(features);
            }
        }

        sw.Stop();
        var totalTests = iterations * testUrls.Length;
        var avgTimeMs = sw.ElapsedMilliseconds / (double)totalTests;
        var throughput = totalTests / sw.Elapsed.TotalSeconds;

        Console.WriteLine($"🏃‍♂️ Total tests: {totalTests:N0}");
        Console.WriteLine($"⏱️ Average time: {avgTimeMs:F3} ms per prediction");
        Console.WriteLine($"🚀 Throughput: {throughput:F0} predictions/second");
        Console.WriteLine($"💾 Memory usage: {GC.GetTotalMemory(false) / 1024 / 1024:F1} MB");
        Console.WriteLine();
    }

    public static async Task RunQuickTest()
    {
        Console.WriteLine("⚡ Quick Feature Extraction Test");
        Console.WriteLine("================");

        var testCases = new[]
        {
            "https://vietcombank.com.vn",
            "http://vietcom-bank.xyz/otp",
            "https://huflit.edu.vn",
            "http://nohu88.club/casino"
        };

        foreach (var url in testCases)
        {
            var features = AIFeatureExtractor.ExtractAdvancedFeatures(url);
            var score = CalculateHeuristicScore(features);
            var risk = (int)(score * 100);
            
            Console.WriteLine($"🔍 {url}");
            Console.WriteLine($"   Risk: {risk}%");
            Console.WriteLine($"   Features: URLLen={features.UrlLength}, HTTP={features.IsHttp}, " +
                            $"OTP={features.ContainsOtpKeyword}, Bank={features.ContainsBankKeyword}");
            Console.WriteLine();
        }
    }
}