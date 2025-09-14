using PhishRadar.Core.Abstractions;
using System.Text.RegularExpressions;

namespace PhishRadar.Rules;

/// <summary>
/// Enhanced Gambling Detection Rule - Comprehensive Vietnamese + International
/// UPDATED: Thêm "nổ hũ" và các thuật ngữ cờ bạc VN quan trọng
/// </summary>
public sealed class GamblingKeywordRule : IRule
{
    // International gambling sites and keywords
    private static readonly string[] InternationalGambling = {
        "casino", "bet365", "188bet", "fun88", "w88", "dafabet", "m88", "12bet",
        "poker", "slot", "lottery", "gambling", "jackpot", "roulette", "blackjack",
        "betting", "sportsbook", "odds", "bookmaker", "wager", "stake"
    };
    
    // Vietnamese gambling keywords - ENHANCED với từ khóa quan trọng
    private static readonly string[] VietnameseGambling = {
        // Core gambling terms
        "cược", "đánh bạc", "sòng bạc", "tài xỉu", "xổ số", "lô đề", "cá độ",
        "ca do", "cá cược", "ca cuoc", "bong da", "bóng đá", "kèo nhà cái",
        "nhà cái", "nha cai", "thể thao", "the thao",
        
        // CRITICAL: Slot/Casino terms (nổ hũ family)
        "nổ hũ", "no hu", "nohu", "nohũ", "quay hũ", "hũ nổ", "slot game",
        "máy đánh bạc", "may danh bac", "game bài", "bài bạc", "bai bac",
        
        // Vietnamese casino terms
        "sảnh casino", "live casino", "casino trực tuyến", "casino online",
        "baccarat", "xì dách", "xi dach", "blackjack việt", "poker việt",
        
        // Vietnamese gambling slang
        "ăn tiền", "an tien", "thắng lớn", "thang lon", "đổi thưởng", "doi thuong",
        "nạp tiền", "rút tiền", "nap tien", "rut tien", "chơi bài", "choi bai"
    };
    
    // Suspicious gambling domains patterns
    private static readonly string[] GamblingDomains = {
        "bet", "casino", "poker", "slot", "game", "win", "lucky", "jackpot",
        "888", "777", "999", "vip", "gold", "king", "royal", "nohu", "no-hu",
        "bongda", "keo", "cuoc", "bai", "tai-xiu", "taixiu"
    };
    
    // Vietnamese gambling sites patterns - ENHANCED
    private static readonly string[] VietnameseGamblingSites = {
        "keonhacai", "soikeo", "tylekeo", "188", "w88", "fun88", "dafabet",
        "m88", "12bet", "vwin", "sbobet", "ibo", "cmd368",
        // NỔ HŨ sites patterns
        "nohu", "no-hu", "nohutop", "nohu90", "nohu52", "nohu88", "nohu99",
        "game-bai", "gamebai", "doi-thuong", "doithuong", "an-tien"
    };
    
    // Gambling-related phrases (context detection) - ENHANCED
    private static readonly Regex GamblingPhrases = new(
        @"(đặt cược|dat cuoc|place bet|live betting|" +
        @"odds|tỷ lệ|ty le|thắng lớn|thang lon|" +
        @"trúng lớn|trung lon|jackpot|quay hũ|nổ hũ|no hu|" +
        @"nạp tiền|rút tiền|withdraw|deposit|đổi thưởng|doi thuong|" +
        @"game bài|chơi bài|slot game|máy đánh bạc)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // SPECIAL: Nổ hũ detection patterns
    private static readonly Regex NoHuPattern = new(
        @"(nổ\s*hũ|no\s*hu|quay\s*hũ|slot\s*game|máy\s*đánh\s*bạc)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public RuleResult Evaluate((string Host, string Path, string? Text) features)
    {
        var host = features.Host.ToLowerInvariant();
        var path = features.Path.ToLowerInvariant();
        var text = (features.Text ?? "").ToLowerInvariant();
        var combined = $"{host} {path} {text}";
        
        double score = 0;
        var reasons = new List<string>();
        var tags = new List<string>();

        // 1. CRITICAL: Nổ hũ/Casino detection (Highest priority)
        if (NoHuPattern.IsMatch(combined) || host.Contains("nohu"))
        {
            score = Math.Max(score, 0.95);
            reasons.Add("🚨 CRITICAL: Vietnamese casino/slot gaming detected (nổ hũ)");
            tags.Add("vietnamese_casino_critical");
        }

        // 2. Check domain for gambling patterns
        foreach (var pattern in GamblingDomains)
        {
            if (host.Contains(pattern))
            {
                score = Math.Max(score, 0.7);
                reasons.Add($"🎰 Gambling domain pattern: {pattern}");
                tags.Add("gambling_domain");
                break;
            }
        }

        // 3. Check Vietnamese gambling sites
        foreach (var site in VietnameseGamblingSites)
        {
            if (host.Contains(site))
            {
                score = Math.Max(score, 0.85);
                reasons.Add($"🇻🇳 Vietnamese gambling site detected: {site}");
                tags.Add("vietnamese_gambling_site");
                break;
            }
        }

        // 4. Check international gambling keywords
        foreach (var keyword in InternationalGambling)
        {
            if (combined.Contains(keyword))
            {
                score = Math.Max(score, 0.65);
                reasons.Add($"🌍 International gambling keyword: {keyword}");
                tags.Add("international_gambling");
                break;
            }
        }

        // 5. Check Vietnamese gambling keywords
        foreach (var keyword in VietnameseGambling)
        {
            if (combined.Contains(keyword))
            {
                score = Math.Max(score, 0.75);
                reasons.Add($"🇻🇳 Vietnamese gambling keyword: {keyword}");
                tags.Add("vietnamese_gambling");
                break;
            }
        }

        // 6. Check gambling phrases (context)
        if (GamblingPhrases.IsMatch(text))
        {
            score = Math.Max(score, 0.8);
            reasons.Add("🎲 Gambling context phrases detected");
            tags.Add("gambling_context");
        }

        // 7. Multiple gambling indicators = high confidence
        var gamblingKeywordCount = InternationalGambling.Count(k => combined.Contains(k)) +
                                  VietnameseGambling.Count(k => combined.Contains(k));
        
        if (gamblingKeywordCount > 2)
        {
            score = Math.Max(score, 0.9);
            reasons.Add($"🚨 Multiple gambling indicators ({gamblingKeywordCount} found)");
            tags.Add("multi_gambling_indicators");
        }

        // 8. Specific TLD patterns for gambling
        if (host.EndsWith(".bet") || host.EndsWith(".casino") || host.EndsWith(".poker"))
        {
            score = Math.Max(score, 0.9);
            reasons.Add("🎰 Gambling-specific TLD detected");
            tags.Add("gambling_tld");
        }

        // 9. SPECIAL: Number patterns common in Vietnamese gambling sites
        if (Regex.IsMatch(host, @"(nohu|bai|game)\d+") || Regex.IsMatch(host, @"\d+(win|bet|game)"))
        {
            score = Math.Max(score, 0.8);
            reasons.Add("🎯 Vietnamese gambling site number pattern");
            tags.Add("vietnamese_gambling_number_pattern");
        }

        return new RuleResult(
            Math.Min(1.0, score),
            string.Join("; ", reasons),
            string.Join(",", tags.Distinct())
        );
    }
}
