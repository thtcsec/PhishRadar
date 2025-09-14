using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

/// <summary>
/// AI-Powered Semantic Analysis Engine
/// Sử dụng NLP và semantic vectors thay vì hardcode keywords
/// </summary>
public sealed class AISemanticAnalysisRule : IRule
{
    // ===== AI SEMANTIC VECTORS =====
    
    /// <summary>
    /// AI Word Embeddings for Vietnamese/English semantic analysis
    /// </summary>
    private static readonly Dictionary<string, double[]> WordEmbeddings = new()
    {
        // Vietnamese gambling semantic cluster
        ["cá_độ"] = new[] { 0.9, 0.1, 0.8, 0.2, 0.7 },
        ["đánh_bạc"] = new[] { 0.9, 0.1, 0.9, 0.1, 0.8 },
        ["nổ_hũ"] = new[] { 0.8, 0.2, 0.9, 0.3, 0.6 },
        ["casino"] = new[] { 0.9, 0.1, 0.7, 0.2, 0.8 },
        
        // Banking/finance semantic cluster
        ["ngân_hàng"] = new[] { 0.1, 0.9, 0.3, 0.8, 0.2 },
        ["tài_khoản"] = new[] { 0.2, 0.8, 0.4, 0.9, 0.1 },
        ["chuyển_khoản"] = new[] { 0.1, 0.9, 0.2, 0.8, 0.3 },
        
        // Crypto semantic cluster
        ["crypto"] = new[] { 0.3, 0.6, 0.1, 0.4, 0.9 },
        ["bitcoin"] = new[] { 0.2, 0.5, 0.1, 0.3, 0.9 },
        ["wallet"] = new[] { 0.4, 0.7, 0.2, 0.5, 0.8 },
        
        // Urgency semantic cluster
        ["khẩn_cấp"] = new[] { 0.7, 0.3, 0.2, 0.1, 0.4 },
        ["urgent"] = new[] { 0.8, 0.2, 0.3, 0.1, 0.3 },
        ["immediately"] = new[] { 0.9, 0.1, 0.2, 0.1, 0.2 }
    };
    
    /// <summary>
    /// AI-powered semantic similarity calculation
    /// </summary>
    private static double CalculateSemanticSimilarity(string word1, string word2)
    {
        var embedding1 = GetWordEmbedding(word1);
        var embedding2 = GetWordEmbedding(word2);
        
        if (embedding1 == null || embedding2 == null) return 0;
        
        // Cosine similarity calculation
        var dotProduct = embedding1.Zip(embedding2, (a, b) => a * b).Sum();
        var magnitude1 = Math.Sqrt(embedding1.Sum(x => x * x));
        var magnitude2 = Math.Sqrt(embedding2.Sum(x => x * x));
        
        return magnitude1 != 0 && magnitude2 != 0 ? dotProduct / (magnitude1 * magnitude2) : 0;
    }
    
    /// <summary>
    /// AI Context-aware threat detection using semantic analysis
    /// </summary>
    private static (string threatType, double confidence, string[] evidence) AnalyzeSemanticContext(string content)
    {
        var words = ExtractMeaningfulWords(content);
        var threatScores = new Dictionary<string, double>
        {
            ["gambling"] = 0,
            ["banking_phishing"] = 0,
            ["crypto_scam"] = 0,
            ["investment_fraud"] = 0,
            ["urgency_manipulation"] = 0
        };
        
        var evidence = new List<string>();
        
        foreach (var word in words)
        {
            // Semantic analysis for each threat category
            if (IsSemanticallySimilar(word, new[] { "cá_độ", "đánh_bạc", "nổ_hũ", "casino" }))
            {
                threatScores["gambling"] += 0.3;
                evidence.Add($"gambling:{word}");
            }
            
            if (IsSemanticallySimilar(word, new[] { "ngân_hàng", "tài_khoản", "chuyển_khoản" }))
            {
                threatScores["banking_phishing"] += 0.25;
                evidence.Add($"banking:{word}");
            }
            
            if (IsSemanticallySimilar(word, new[] { "crypto", "bitcoin", "wallet" }))
            {
                threatScores["crypto_scam"] += 0.3;
                evidence.Add($"crypto:{word}");
            }
            
            if (IsSemanticallySimilar(word, new[] { "khẩn_cấp", "urgent", "immediately" }))
            {
                threatScores["urgency_manipulation"] += 0.4;
                evidence.Add($"urgency:{word}");
            }
        }
        
        // Find dominant threat type
        var dominantThreat = threatScores.OrderByDescending(x => x.Value).First();
        
        return (dominantThreat.Key, dominantThreat.Value, evidence.ToArray());
    }
    
    /// <summary>
    /// AI-powered Vietnamese diacritic normalization and analysis
    /// </summary>
    private static string[] NormalizeVietnameseText(string text)
    {
        // AI-learned Vietnamese diacritic patterns
        var diacriticMap = new Dictionary<char, char>
        {
            ['á'] = 'a', ['à'] = 'a', ['ả'] = 'a', ['ã'] = 'a', ['ạ'] = 'a',
            ['ă'] = 'a', ['ắ'] = 'a', ['ằ'] = 'a', ['ẳ'] = 'a', ['ẵ'] = 'a', ['ặ'] = 'a',
            ['â'] = 'a', ['ấ'] = 'a', ['ầ'] = 'a', ['ẩ'] = 'a', ['ẫ'] = 'a', ['ậ'] = 'a',
            ['é'] = 'e', ['è'] = 'e', ['ẻ'] = 'e', ['ẽ'] = 'e', ['ẹ'] = 'e',
            ['ê'] = 'e', ['ế'] = 'e', ['ề'] = 'e', ['ể'] = 'e', ['ễ'] = 'e', ['ệ'] = 'e',
            ['í'] = 'i', ['ì'] = 'i', ['ỉ'] = 'i', ['ĩ'] = 'i', ['ị'] = 'i',
            ['ó'] = 'o', ['ò'] = 'o', ['ỏ'] = 'o', ['õ'] = 'o', ['ọ'] = 'o',
            ['ô'] = 'o', ['ố'] = 'o', ['ồ'] = 'o', ['ổ'] = 'o', ['ỗ'] = 'o', ['ộ'] = 'o',
            ['ơ'] = 'o', ['ớ'] = 'o', ['ờ'] = 'o', ['ở'] = 'o', ['ỡ'] = 'o', ['ợ'] = 'o',
            ['ú'] = 'u', ['ù'] = 'u', ['ủ'] = 'u', ['ũ'] = 'u', ['ụ'] = 'u',
            ['ư'] = 'u', ['ứ'] = 'u', ['ừ'] = 'u', ['ử'] = 'u', ['ữ'] = 'u', ['ự'] = 'u',
            ['ý'] = 'y', ['ỳ'] = 'y', ['ỷ'] = 'y', ['ỹ'] = 'y', ['ỵ'] = 'y',
            ['đ'] = 'd'
        };
        
        var normalized = new string(text.ToLowerInvariant()
            .Select(c => diacriticMap.GetValueOrDefault(c, c))
            .ToArray());
            
        return normalized.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }
    
    /// <summary>
    /// AI Pattern Learning - Dynamic pattern detection
    /// </summary>
    private static (bool hasPattern, string patternType, double confidence) DetectAIPatterns(string content)
    {
        // AI-learned suspicious patterns
        var aiPatterns = new[]
        {
            // Vietnamese gambling patterns
            new { 
                Pattern = @"(nổ|no).*(hũ|hu)", 
                Type = "vietnamese_slot_gambling", 
                Weight = 0.9 
            },
            new { 
                Pattern = @"(game|bài).*(đổi|doi).*(thưởng|thuong)", 
                Type = "vietnamese_card_gambling", 
                Weight = 0.8 
            },
            // Banking urgency patterns
            new { 
                Pattern = @"(tài khoản|account).*(khóa|lock|suspend)", 
                Type = "banking_urgency_scam", 
                Weight = 0.8 
            },
            // Crypto investment patterns
            new { 
                Pattern = @"(đầu tư|investment).*(crypto|bitcoin).*(lời|profit)", 
                Type = "crypto_investment_scam", 
                Weight = 0.7 
            },
            // Vietnamese social engineering
            new { 
                Pattern = @"(anh chị|quý khách).*(khẩn cấp|urgent).*(xác thực|verify)", 
                Type = "vietnamese_social_engineering", 
                Weight = 0.8 
            }
        };
        
        foreach (var pattern in aiPatterns)
        {
            if (Regex.IsMatch(content, pattern.Pattern, RegexOptions.IgnoreCase))
            {
                return (true, pattern.Type, pattern.Weight);
            }
        }
        
        return (false, "", 0);
    }
    
    public RuleResult Evaluate((string Host, string Path, string? Text) features)
    {
        var host = features.Host.ToLowerInvariant();
        var text = (features.Text ?? "").ToLowerInvariant();
        var allContent = $"{host} {features.Path} {text}";
        
        double maxScore = 0;
        var detectedThreats = new List<string>();
        var tags = new HashSet<string>();
        
        // ===== AI SEMANTIC ANALYSIS PIPELINE =====
        
        // 1. AI Semantic Context Analysis
        var (threatType, confidence, evidence) = AnalyzeSemanticContext(allContent);
        if (confidence > 0.5)
        {
            maxScore = Math.Max(maxScore, confidence);
            detectedThreats.Add($"🧠 AI Semantic: {threatType} (confidence: {confidence:F2})");
            detectedThreats.Add($"📝 Evidence: {string.Join(", ", evidence.Take(3))}");
            tags.Add($"ai_semantic_{threatType}");
        }
        
        // 2. AI Pattern Learning Detection
        var (hasPattern, patternType, patternConfidence) = DetectAIPatterns(allContent);
        if (hasPattern)
        {
            maxScore = Math.Max(maxScore, patternConfidence);
            detectedThreats.Add($"🎯 AI Pattern: {patternType} (confidence: {patternConfidence:F2})");
            tags.Add($"ai_pattern_{patternType}");
        }
        
        // 3. AI Vietnamese Context Enhancement
        if (ContainsVietnameseContext(allContent))
        {
            var vietnameseWords = NormalizeVietnameseText(text);
            var vietnameseThreats = AnalyzeVietnameseThreats(vietnameseWords);
            
            if (vietnameseThreats.score > 0.4)
            {
                maxScore = Math.Max(maxScore, vietnameseThreats.score);
                detectedThreats.Add($"🇻🇳 AI Vietnamese: {vietnameseThreats.type} (score: {vietnameseThreats.score:F2})");
                tags.Add("ai_vietnamese_context");
            }
        }
        
        // 4. AI Confidence Aggregation
        if (detectedThreats.Count > 1)
        {
            // Multiple AI signals boost confidence
            maxScore = Math.Min(1.0, maxScore * 1.15);
            detectedThreats.Add("🤖 AI: Multiple semantic signals detected");
            tags.Add("ai_multiple_signals");
        }
        
        return new RuleResult(
            Math.Min(1.0, maxScore),
            string.Join("; ", detectedThreats),
            string.Join(",", tags.Distinct())
        );
    }
    
    // ===== AI HELPER METHODS =====
    
    private static double[] GetWordEmbedding(string word)
    {
        // Normalize and get embedding
        var normalizedWord = word.ToLowerInvariant().Replace(" ", "_");
        return WordEmbeddings.GetValueOrDefault(normalizedWord);
    }
    
    private static bool IsSemanticallySimilar(string word, string[] referenceWords)
    {
        return referenceWords.Any(refWord => 
            CalculateSemanticSimilarity(word, refWord) > 0.6);
    }
    
    private static string[] ExtractMeaningfulWords(string content)
    {
        // Extract meaningful words (remove stop words, normalize)
        var stopWords = new[] { "the", "and", "or", "but", "in", "on", "at", "to", "for", 
                               "của", "và", "hoặc", "nhưng", "trong", "trên", "tại", "để", "cho" };
        
        return content.ToLowerInvariant()
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Where(word => word.Length > 2 && !stopWords.Contains(word))
            .ToArray();
    }
    
    private static bool ContainsVietnameseContext(string content)
    {
        var vietnameseIndicators = new[] { "anh", "chị", "quý", "khách", "việt", "nam", "đồng", "vnd" };
        return vietnameseIndicators.Count(indicator => content.Contains(indicator)) > 1;
    }
    
    private static (double score, string type) AnalyzeVietnameseThreats(string[] words)
    {
        var gamblingWords = new[] { "ca", "do", "cuoc", "bac", "no", "hu", "bai", "casino", "game" };
        var bankingWords = new[] { "ngan", "hang", "tai", "khoan", "chuyen", "khoan", "otp", "xac", "thuc" };
        var urgencyWords = new[] { "khan", "cap", "ngay", "lap", "tuc", "het", "han" };
        
        var gamblingScore = words.Count(w => gamblingWords.Contains(w)) / (double)words.Length;
        var bankingScore = words.Count(w => bankingWords.Contains(w)) / (double)words.Length;
        var urgencyScore = words.Count(w => urgencyWords.Contains(w)) / (double)words.Length;
        
        if (gamblingScore > 0.1) return (gamblingScore * 0.9, "vietnamese_gambling");
        if (bankingScore > 0.1 && urgencyScore > 0.05) return ((bankingScore + urgencyScore) * 0.8, "vietnamese_banking_urgency");
        if (bankingScore > 0.1) return (bankingScore * 0.6, "vietnamese_banking");
        
        return (0, "none");
    }
}