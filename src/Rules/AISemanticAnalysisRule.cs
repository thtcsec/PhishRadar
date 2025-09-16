using System.Text.RegularExpressions;
using System.Text;
using System.Globalization;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

/// <summary>
/// AI-Powered Semantic Analysis Engine - ENHANCED VERSION
/// Uses proper NLP tokenization and semantic vectors for threat detection
/// </summary>
public sealed class AISemanticAnalysisRule : IRule
{
    // ===== PROPER TOKENIZATION =====
    
    private static readonly Regex WordRegex = new(
        @"[\p{L}\p{Nd}_]+", 
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));
    
    private static readonly HashSet<string> StopWordsVN = new(StringComparer.Ordinal)
    {
        "va", "và", "la", "là", "cua", "của", "cho", "de", "để", "trong", "tren", "trên", 
        "tai", "tại", "nguoi", "người", "nay", "này", "do", "được", "co", "có", "se", "sẽ",
        "the", "and", "or", "but", "in", "on", "at", "to", "for", "is", "are", "was", "were"
    };
    
    private static readonly Regex VietnameseLetterRegex = new(
        @"[ăâđêôơưáàảãạắằẳẵặấầẩẫậéèẻẽẹếềểễệíìỉĩịóòỏõỌốồổỗộớờởỡợúùủũụứừửữựýỳỷỹỵ]",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    
    // ===== AI SEMANTIC VECTORS (CANONICAL KEYS) =====
    
    private static readonly Dictionary<string, double[]> WordEmbeddings = new()
    {
        // Vietnamese gambling semantic cluster (canonical form)
        ["ca_do"] = new[] { 0.9, 0.1, 0.8, 0.2, 0.7 },
        ["danh_bac"] = new[] { 0.9, 0.1, 0.9, 0.1, 0.8 },
        ["no_hu"] = new[] { 0.8, 0.2, 0.9, 0.3, 0.6 },
        ["casino"] = new[] { 0.9, 0.1, 0.7, 0.2, 0.8 },
        ["game_bai"] = new[] { 0.8, 0.2, 0.8, 0.3, 0.7 },
        ["doi_thuong"] = new[] { 0.7, 0.3, 0.8, 0.4, 0.6 },
        
        // Banking/finance semantic cluster
        ["ngan_hang"] = new[] { 0.1, 0.9, 0.3, 0.8, 0.2 },
        ["tai_khoan"] = new[] { 0.2, 0.8, 0.4, 0.9, 0.1 },
        ["chuyen_khoan"] = new[] { 0.1, 0.9, 0.2, 0.8, 0.3 },
        ["vietcombank"] = new[] { 0.1, 0.9, 0.3, 0.8, 0.2 },
        ["techcombank"] = new[] { 0.1, 0.9, 0.3, 0.8, 0.2 },
        ["banking"] = new[] { 0.1, 0.9, 0.3, 0.8, 0.2 },
        
        // Crypto semantic cluster
        ["crypto"] = new[] { 0.3, 0.6, 0.1, 0.4, 0.9 },
        ["bitcoin"] = new[] { 0.2, 0.5, 0.1, 0.3, 0.9 },
        ["wallet"] = new[] { 0.4, 0.7, 0.2, 0.5, 0.8 },
        ["blockchain"] = new[] { 0.3, 0.5, 0.1, 0.4, 0.9 },
        
        // Urgency semantic cluster
        ["khan_cap"] = new[] { 0.7, 0.3, 0.2, 0.1, 0.4 },
        ["urgent"] = new[] { 0.8, 0.2, 0.3, 0.1, 0.3 },
        ["immediately"] = new[] { 0.9, 0.1, 0.2, 0.1, 0.2 },
        ["ngay_lap_tuc"] = new[] { 0.8, 0.2, 0.3, 0.1, 0.3 },
        
        // Security/Auth cluster
        ["xac_thuc"] = new[] { 0.4, 0.6, 0.8, 0.2, 0.3 },
        ["otp"] = new[] { 0.3, 0.7, 0.9, 0.1, 0.2 },
        ["verify"] = new[] { 0.4, 0.6, 0.8, 0.2, 0.3 },
        ["login"] = new[] { 0.3, 0.7, 0.7, 0.3, 0.2 }
    };
    
    // ===== PROPER TEXT NORMALIZATION =====
    
    /// <summary>
    /// Normalize text: Unicode NFC/NFD + remove diacritics + lowercase
    /// </summary>
    private static string NormalizeNoDiacritics(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        
        // Unicode normalization
        var formD = input.Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder(formD.Length);
        
        foreach (var ch in formD)
        {
            var uc = CharUnicodeInfo.GetUnicodeCategory(ch);
            if (uc != UnicodeCategory.NonSpacingMark)
                sb.Append(ch);
        }
        
        // Handle đ/Đ specifically
        return sb.ToString()
                 .Normalize(NormalizationForm.FormC)
                 .Replace('Đ', 'D')
                 .Replace('đ', 'd')
                 .ToLowerInvariant();
    }
    
    /// <summary>
    /// Proper tokenization: extract letters/digits/underscores, filter short tokens
    /// </summary>
    private static string[] Tokenize(string content)
    {
        if (string.IsNullOrEmpty(content)) return Array.Empty<string>();
        
        try
        {
            return WordRegex.Matches(content)
                .Select(m => m.Value)
                .Where(t => t.Length > 1 && !StopWordsVN.Contains(t))
                .ToArray();
        }
        catch (RegexMatchTimeoutException)
        {
            return Array.Empty<string>();
        }
    }
    
    /// <summary>
    /// Convert token to canonical form for embedding lookup
    /// </summary>
    private static string ToCanonical(string token)
    {
        var normalized = NormalizeNoDiacritics(token);
        return normalized.Replace(' ', '_');
    }
    
    // ===== SEMANTIC SIMILARITY =====
    
    /// <summary>
    /// Calculate cosine similarity between word embeddings
    /// </summary>
    private static double CalculateSemanticSimilarity(string word1, string word2)
    {
        var embedding1 = GetWordEmbedding(word1);
        var embedding2 = GetWordEmbedding(word2);
        
        if (embedding1 == null || embedding2 == null) return 0;
        
        // Cosine similarity
        var dotProduct = embedding1.Zip(embedding2, (a, b) => a * b).Sum();
        var magnitude1 = Math.Sqrt(embedding1.Sum(x => x * x));
        var magnitude2 = Math.Sqrt(embedding2.Sum(x => x * x));
        
        return magnitude1 != 0 && magnitude2 != 0 ? dotProduct / (magnitude1 * magnitude2) : 0;
    }
    
    private static double[]? GetWordEmbedding(string word)
    {
        var canonical = ToCanonical(word);
        return WordEmbeddings.GetValueOrDefault(canonical);
    }
    
    private static bool IsSemanticallySimilar(string token, params string[] referenceCanonicals)
    {
        var canonical = ToCanonical(token);
        return referenceCanonicals.Any(refCanonical => 
            CalculateSemanticSimilarity(canonical, refCanonical) > 0.6);
    }
    
    // ===== SAFE REGEX PATTERNS =====
    
    private static bool IsMatchSafe(string input, string pattern)
    {
        try
        {
            return Regex.IsMatch(input, pattern,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
                TimeSpan.FromMilliseconds(50));
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
    
    // ===== AI SEMANTIC ANALYSIS =====
    
    /// <summary>
    /// AI semantic context analysis with proper token normalization
    /// </summary>
    private static (string threatType, double confidence, string[] evidence) AnalyzeSemanticContext(string[] tokens)
    {
        var threatScores = new Dictionary<string, double>
        {
            ["gambling"] = 0,
            ["banking_phishing"] = 0,
            ["crypto_scam"] = 0,
            ["urgency_manipulation"] = 0,
            ["authentication_fraud"] = 0
        };
        
        var evidence = new List<string>();
        
        // Semantic category references (canonical)
        var gamblingRefs = new[] { "ca_do", "danh_bac", "no_hu", "casino", "game_bai", "doi_thuong" };
        var bankingRefs = new[] { "ngan_hang", "tai_khoan", "chuyen_khoan", "vietcombank", "techcombank" };
        var cryptoRefs = new[] { "crypto", "bitcoin", "wallet", "blockchain" };
        var urgencyRefs = new[] { "khan_cap", "urgent", "immediately", "ngay_lap_tuc" };
        var authRefs = new[] { "xac_thuc", "otp", "verify", "login" };
        
        foreach (var token in tokens)
        {
            if (IsSemanticallySimilar(token, gamblingRefs))
            {
                threatScores["gambling"] += 0.3;
                evidence.Add($"gambling:{token}");
            }
            
            if (IsSemanticallySimilar(token, bankingRefs))
            {
                threatScores["banking_phishing"] += 0.25;
                evidence.Add($"banking:{token}");
            }
            
            if (IsSemanticallySimilar(token, cryptoRefs))
            {
                threatScores["crypto_scam"] += 0.3;
                evidence.Add($"crypto:{token}");
            }
            
            if (IsSemanticallySimilar(token, urgencyRefs))
            {
                threatScores["urgency_manipulation"] += 0.4;
                evidence.Add($"urgency:{token}");
            }
            
            if (IsSemanticallySimilar(token, authRefs))
            {
                threatScores["authentication_fraud"] += 0.2;
                evidence.Add($"auth:{token}");
            }
        }
        
        // Find dominant threat type
        var dominantThreat = threatScores.OrderByDescending(x => x.Value).First();
        
        return (dominantThreat.Key, dominantThreat.Value, evidence.ToArray());
    }
    
    /// <summary>
    /// AI pattern detection with safe regex and timeout protection
    /// </summary>
    private static (bool hasPattern, string patternType, double confidence) DetectAIPatterns(string content)
    {
        var aiPatterns = new[]
        {
            new { Pattern = @"(no|nổ).*(hu|hũ)", Type = "vietnamese_slot_gambling", Weight = 0.9 },
            new { Pattern = @"(game|bai|bài).*(doi|đổi).*(thuong|thưởng)", Type = "vietnamese_card_gambling", Weight = 0.8 },
            new { Pattern = @"(tai|tài).*(khoan|khoản).*(khoa|khóa|lock|suspend)", Type = "banking_urgency_scam", Weight = 0.8 },
            new { Pattern = @"(dau|đầu).*(tu|tư).*(crypto|bitcoin).*(loi|lời|profit)", Type = "crypto_investment_scam", Weight = 0.7 },
            new { Pattern = @"(anh|chi|chị).*(quy|quý).*(khach|khách).*(khan|khẩn).*(cap|cấp)", Type = "vietnamese_social_engineering", Weight = 0.8 },
            new { Pattern = @"(mien|miễn).*(phi|phí|free).*(qua|quà).*(tang|tặng|gift)", Type = "vietnamese_free_gift_scam", Weight = 0.6 },
            new { Pattern = @"(chuyen|chuyển).*(khoan|khoản).*(nhanh|fast).*(nhan|nhận)", Type = "vietnamese_quick_transfer_scam", Weight = 0.7 }
        };
        
        foreach (var pattern in aiPatterns)
        {
            if (IsMatchSafe(content, pattern.Pattern))
            {
                return (true, pattern.Type, pattern.Weight);
            }
        }
        
        return (false, "", 0);
    }
    
    /// <summary>
    /// Improved Vietnamese context detection
    /// </summary>
    private static bool LooksVietnamese(string content)
    {
        if (string.IsNullOrEmpty(content)) return false;
        
        try
        {
            return VietnameseLetterRegex.IsMatch(content);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
    
    /// <summary>
    /// Enhanced Vietnamese threat analysis with proper token normalization
    /// </summary>
    private static (double score, string type) AnalyzeVietnameseThreats(string[] tokensNormalized)
    {
        var filteredTokens = tokensNormalized
            .Where(t => !StopWordsVN.Contains(t) && t.Length > 1)
            .ToArray();
            
        if (filteredTokens.Length == 0) return (0, "none");
        
        var gambling = new HashSet<string>(StringComparer.Ordinal) 
        { 
            "ca", "do", "cuoc", "bac", "no", "hu", "bai", "casino", "game", "doi", "thuong",
            "slot", "jackpot", "win", "lucky"
        };
        
        var banking = new HashSet<string>(StringComparer.Ordinal)
        { 
            "ngan", "hang", "tai", "khoan", "chuyen", "otp", "xac", "thuc", "vietcombank", 
            "techcombank", "bidv", "acb", "vpbank", "agribank", "login", "verify"
        };
        
        var urgency = new HashSet<string>(StringComparer.Ordinal)
        { 
            "khan", "cap", "ngay", "lap", "tuc", "het", "han", "urgent", "immediate", "now"
        };
        
        double gamblingScore = filteredTokens.Count(gambling.Contains) / (double)filteredTokens.Length;
        double bankingScore = filteredTokens.Count(banking.Contains) / (double)filteredTokens.Length;
        double urgencyScore = filteredTokens.Count(urgency.Contains) / (double)filteredTokens.Length;
        
        if (gamblingScore > 0.08) return (Math.Min(1.0, gamblingScore * 0.9), "vietnamese_gambling");
        if (bankingScore > 0.07 && urgencyScore > 0.04) return (Math.Min(1.0, (bankingScore + urgencyScore) * 0.8), "vietnamese_banking_urgency");
        if (bankingScore > 0.08) return (Math.Min(1.0, bankingScore * 0.6), "vietnamese_banking");
        
        return (0, "none");
    }
    
    /// <summary>
    /// Smart score combination (not just max)
    /// </summary>
    private static double CombineScores(params double[] scores)
    {
        if (scores.Length == 0) return 0;
        
        var validScores = scores.Where(s => s > 0).ToArray();
        if (validScores.Length == 0) return 0;
        
        // Weighted sum with diminishing returns for overlapping signals
        var totalScore = validScores.Sum();
        var overlapPenalty = 0.1 * validScores.Count(s => s > 0.5);
        
        return Math.Min(1.0, totalScore - overlapPenalty);
    }
    
    // ===== MAIN EVALUATION METHOD =====
    
    public RuleResult Evaluate((string Host, string Path, string? Text) features)
    {
        var host = features.Host ?? string.Empty;
        var path = features.Path ?? string.Empty;
        var text = features.Text ?? string.Empty;
        
        // Comprehensive content with both original and normalized versions
        var allContent = string.Join(" ", host, path, text, 
                                    NormalizeNoDiacritics(host), 
                                    NormalizeNoDiacritics(text));
        
        var tokens = Tokenize(allContent);
        var normalizedTokens = tokens.Select(ToCanonical).ToArray();
        
        var detectedThreats = new List<string>();
        var tags = new HashSet<string>();
        var scores = new List<double>();
        var signalCount = 0;
        
        // 1. AI Semantic Context Analysis
        var (threatType, confidence, evidence) = AnalyzeSemanticContext(tokens);
        if (confidence > 0.5)
        {
            scores.Add(confidence);
            detectedThreats.Add($"AI Semantic: {threatType} (confidence: {confidence:F2})");
            detectedThreats.Add($"Evidence: {string.Join(", ", evidence.Take(3))}");
            tags.Add($"ai_semantic_{threatType}");
            signalCount++;
        }
        
        // 2. AI Pattern Learning Detection
        var (hasPattern, patternType, patternConfidence) = DetectAIPatterns(allContent);
        if (hasPattern)
        {
            scores.Add(patternConfidence);
            detectedThreats.Add($"AI Pattern: {patternType} (confidence: {patternConfidence:F2})");
            tags.Add($"ai_pattern_{patternType}");
            signalCount++;
        }
        
        // 3. Vietnamese Context Enhancement
        if (LooksVietnamese(allContent))
        {
            var vietnameseThreats = AnalyzeVietnameseThreats(normalizedTokens);
            
            if (vietnameseThreats.score > 0.4)
            {
                scores.Add(vietnameseThreats.score);
                detectedThreats.Add($"AI Vietnamese: {vietnameseThreats.type} (score: {vietnameseThreats.score:F2})");
                tags.Add("ai_vietnamese_context");
                tags.Add($"vietnamese_{vietnameseThreats.type}");
                signalCount++;
            }
        }
        
        // 4. Smart Score Combination
        var finalScore = CombineScores(scores.ToArray());
        
        // Add multiple signals tag if we have more than one detection
        if (signalCount > 1)
        {
            detectedThreats.Add("AI: Multiple semantic signals detected");
            tags.Add("ai_multiple_signals");
        }
        
        return new RuleResult(
            finalScore,
            string.Join("; ", detectedThreats),
            string.Join(",", tags.Distinct())
        );
    }
}