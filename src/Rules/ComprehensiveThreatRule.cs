using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

/// <summary>
/// Comprehensive Threat Detection Engine - Phát hiện mọi loại scam/gambling
/// Intelligence cao nhất, không bỏ lỡ bất kỳ threat nào
/// </summary>
public sealed class ComprehensiveThreatRule : IRule
{
    // ===== CRYPTO EXCHANGE IMPERSONATION =====
    private static readonly Dictionary<string, string> LegitimateExchanges = new()
    {
        ["binance"] = "binance.com",
        ["coinbase"] = "coinbase.com", 
        ["kraken"] = "kraken.com",
        ["bitfinex"] = "bitfinex.com",
        ["coinbene"] = "coinbene.com",
        ["huobi"] = "huobi.com",
        ["okx"] = "okx.com",
        ["kucoin"] = "kucoin.com",
        ["bybit"] = "bybit.com",
        ["gate"] = "gate.io"
    };

    // ===== VIETNAMESE GAMBLING COMPREHENSIVE =====
    private static readonly string[] VietnameseGamblingComplete = {
        // Nổ hũ family
        "nohu", "no-hu", "nohutop", "nohu90", "nohu88", "nohu99", "nohu52", "nohu68", "nohu77",
        "quay-hu", "quayhu", "slot-game", "slotgame",
        
        // Game bài family
        "game-bai", "gamebai", "bai-doi-thuong", "baidoithuong", "doi-thuong", "doithuong",
        "game-doi-thuong", "gamedoithuong", "choi-bai", "choibai",
        
        // Casino Vietnamese
        "casino-vn", "casinovn", "live-casino", "livecasino", "casino-online", "casinoonline",
        "sanhcasino", "sanh-casino",
        
        // Cá độ variations
        "ca-do", "cado", "ca-cuoc", "cacuoc", "dat-cuoc", "datcuoc",
        "cado-bong-da", "cadobongda", "bong-da-88", "bongda88",
        
        // Specific sites
        "fun88", "w88", "188bet", "12bet", "dafabet", "kubet", "vwin", "m88",
        "sunwin", "hitclub", "rikvip", "b52", "tai-xiu", "taixiu",
        
        // Money-related gambling
        "an-tien", "antien", "kiem-tien", "kiemtien", "lam-giau", "lamgiau",
        "thang-lon", "thanglon", "trung-thuong", "trungthuong"
    };

    // ===== INTERNATIONAL GAMBLING COMPREHENSIVE =====
    private static readonly string[] InternationalGamblingComplete = {
        // Casino keywords
        "casino", "gambling", "jackpot", "slot", "poker", "roulette", "blackjack", "baccarat",
        "dice", "wheel", "fortune", "lucky", "vegas", "monte-carlo", "macau",
        
        // Betting keywords
        "bet", "betting", "wager", "stake", "odds", "bookmaker", "sportsbook",
        "bet365", "betway", "betfair", "paddypower",
        
        // Lottery & games
        "lottery", "lotto", "powerball", "megamillions", "scratch", "instant-win",
        "prize", "jackpot", "winner", "millionaire"
    };

    // ===== SUSPICIOUS TLD PATTERNS =====
    private static readonly string[] SuspiciousTlds = {
        ".tk", ".ml", ".ga", ".cf", ".club", ".xyz", ".top", ".click", ".download",
        ".stream", ".science", ".racing", ".win", ".bid", ".loan", ".cricket",
        ".party", ".work", ".date", ".faith", ".trade", ".accountant"
    };

    // ===== FAKE BRAND INDICATORS =====
    private static readonly Regex FakeBrandPattern = new(
        @"(vietcom|techcom|bidv|acb|vpbank|agribank|binance|coinbase|kraken).*\.(tk|ml|ga|cf|club|xyz|eu\.com|co\.uk|net\.au)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // ===== TYPOSQUATTING PATTERNS =====
    private static readonly Regex TyposquattingPattern = new(
        @"(viet-com|tech-com|bi-dv|a-cb|vp-bank|agri-bank|" +
        @"binance\d+|coinbase\d+|crypto-.*|wallet-.*|" +
        @"metamask-.*|trust-wallet|phantom-wallet)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // ===== FINANCIAL SCAM PATTERNS =====
    private static readonly string[] FinancialScamKeywords = {
        "double-your-money", "guaranteed-profit", "risk-free", "easy-money",
        "get-rich-quick", "investment-opportunity", "crypto-mining",
        "trading-bot", "automated-trading", "signal-group",
        "nhan-doi-tien", "loi-nhuan-dam-bao", "khong-rui-ro", "giau-nhanh"
    };

    public RuleResult Evaluate((string Host, string Path, string? Text) features)
    {
        var host = features.Host.ToLowerInvariant();
        var path = features.Path.ToLowerInvariant();
        var text = (features.Text ?? "").ToLowerInvariant();
        var fullDomain = $"{host}{path}";
        var allContent = $"{host} {path} {text}";

        double maxScore = 0;
        var detectedThreats = new List<string>();
        var tags = new HashSet<string>();

        // ===== 1. CRYPTO EXCHANGE IMPERSONATION (HIGHEST PRIORITY) =====
        foreach (var (exchange, legitimateDomain) in LegitimateExchanges)
        {
            if (host.Contains(exchange) && !host.Equals(legitimateDomain))
            {
                // Check for suspicious patterns
                if (host.EndsWith(".eu.com") || host.EndsWith(".co.uk") || 
                    SuspiciousTlds.Any(tld => host.EndsWith(tld)))
                {
                    maxScore = Math.Max(maxScore, 0.95);
                    detectedThreats.Add($"🚨 CRITICAL: {exchange} exchange impersonation with fake TLD");
                    tags.Add("crypto_exchange_impersonation");
                }
                else if (host != legitimateDomain)
                {
                    maxScore = Math.Max(maxScore, 0.8);
                    detectedThreats.Add($"⚠️ Suspicious {exchange} domain variation");
                    tags.Add("crypto_suspicious_domain");
                }
            }
        }

        // ===== 2. FAKE BRAND DETECTION =====
        if (FakeBrandPattern.IsMatch(host))
        {
            maxScore = Math.Max(maxScore, 0.9);
            detectedThreats.Add("🎭 Brand impersonation with suspicious TLD");
            tags.Add("brand_impersonation");
        }

        // ===== 3. TYPOSQUATTING DETECTION =====
        if (TyposquattingPattern.IsMatch(host))
        {
            maxScore = Math.Max(maxScore, 0.85);
            detectedThreats.Add("🎯 Typosquatting attack detected");
            tags.Add("typosquatting");
        }

        // ===== 4. VIETNAMESE GAMBLING COMPREHENSIVE =====
        var vietnameseGamblingMatches = VietnameseGamblingComplete
            .Where(keyword => allContent.Contains(keyword)).ToArray();
        
        if (vietnameseGamblingMatches.Length > 0)
        {
            maxScore = Math.Max(maxScore, 0.9);
            detectedThreats.Add($"🇻🇳 Vietnamese gambling: {string.Join(", ", vietnameseGamblingMatches.Take(3))}");
            tags.Add("vietnamese_gambling_comprehensive");
        }

        // ===== 5. INTERNATIONAL GAMBLING COMPREHENSIVE =====
        var internationalGamblingMatches = InternationalGamblingComplete
            .Where(keyword => allContent.Contains(keyword)).ToArray();
        
        if (internationalGamblingMatches.Length > 0)
        {
            maxScore = Math.Max(maxScore, 0.8);
            detectedThreats.Add($"🌍 International gambling: {string.Join(", ", internationalGamblingMatches.Take(3))}");
            tags.Add("international_gambling_comprehensive");
        }

        // ===== 6. FINANCIAL SCAM DETECTION =====
        var financialScamMatches = FinancialScamKeywords
            .Where(keyword => allContent.Contains(keyword)).ToArray();
        
        if (financialScamMatches.Length > 0)
        {
            maxScore = Math.Max(maxScore, 0.8);
            detectedThreats.Add($"💰 Financial scam indicators: {string.Join(", ", financialScamMatches.Take(2))}");
            tags.Add("financial_scam");
        }

        // ===== 7. SUSPICIOUS TLD WITH GAMBLING/CRYPTO CONTENT =====
        if (SuspiciousTlds.Any(tld => host.EndsWith(tld)))
        {
            if (allContent.Contains("bet") || allContent.Contains("casino") || 
                allContent.Contains("crypto") || allContent.Contains("wallet"))
            {
                maxScore = Math.Max(maxScore, 0.75);
                detectedThreats.Add("⚠️ Suspicious TLD with gambling/crypto content");
                tags.Add("suspicious_tld_gambling");
            }
        }

        // ===== 8. DOMAIN LENGTH & COMPLEXITY ANALYSIS =====
        if (host.Length > 20 && (host.Count(c => c == '-') > 2 || host.Count(char.IsDigit) > 3))
        {
            maxScore = Math.Max(maxScore, 0.4);
            detectedThreats.Add("🔍 Suspicious domain complexity");
            tags.Add("domain_complexity");
        }

        // ===== 9. MULTIPLE THREAT INDICATORS =====
        if (detectedThreats.Count > 2)
        {
            maxScore = Math.Min(1.0, maxScore * 1.2); // Boost for multiple threats
            detectedThreats.Add($"🎯 Multiple threat vectors ({detectedThreats.Count})");
            tags.Add("multi_threat_vectors");
        }

        // ===== 10. SPECIAL VIETNAMESE CONTEXT =====
        if (IsVietnameseContext(allContent))
        {
            maxScore = Math.Min(1.0, maxScore * 1.1); // Boost for Vietnamese context
            tags.Add("vietnamese_context");
        }

        return new RuleResult(
            Math.Min(1.0, maxScore),
            string.Join("; ", detectedThreats),
            string.Join(",", tags.Distinct())
        );
    }

    private bool IsVietnameseContext(string content)
    {
        var vietnameseIndicators = new[] {
            "viet", "vietnam", "saigon", "hanoi", "hcm", "tphcm",
            "dong", "vnd", "ngan hang", "tai khoan", "chuyen khoan"
        };
        
        return vietnameseIndicators.Count(indicator => content.Contains(indicator)) > 1;
    }
}