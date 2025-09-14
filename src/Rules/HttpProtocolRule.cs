using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

/// <summary>
/// HTTP Protocol Risk Rule - detects sensitive operations that should use HTTPS
/// Works in conjunction with the main analyzer to penalize HTTP protocols
/// </summary>
public sealed class HttpProtocolRule : IRule
{
    private static readonly string[] SensitiveKeywords = {
        // Banking & Finance
        "bank", "banking", "login", "signin", "password", "otp", "verify", "account",
        "payment", "credit", "card", "wallet", "transfer", "deposit", "withdraw",
        
        // Vietnamese Banking
        "vietcombank", "techcombank", "bidv", "acb", "vpbank", "agribank", "momo",
        "zalopay", "airpay", "vnpay", "napas",
        
        // Gambling (high-risk HTTP sites)
        "casino", "bet", "betting", "poker", "slot", "lottery", "gambling",
        "cado", "ca-do", "bongda", "keo", "odds", "188bet", "fun88", "w88",
        
        // Crypto & Web3
        "crypto", "bitcoin", "ethereum", "metamask", "wallet", "exchange", "trading"
    };

    private static readonly string[] GamblingSpecific = {
        "casino", "bet", "betting", "poker", "slot", "lottery", "gambling", "jackpot",
        "cado", "ca-do", "bongda", "keo", "odds", "188bet", "fun88", "w88", "dafabet"
    };

    public RuleResult Evaluate((string Host, string Path, string? Text) f)
    {
        var host = f.Host.ToLowerInvariant();
        var path = f.Path.ToLowerInvariant();
        var text = (f.Text ?? "").ToLowerInvariant();
        
        // Check for gambling content - always risky regardless of protocol
        var gamblingMatches = GamblingSpecific.Where(keyword => 
            host.Contains(keyword) || path.Contains(keyword) || text.Contains(keyword)).ToArray();
            
        if (gamblingMatches.Any())
        {
            return new RuleResult(0.45, 
                $"Gambling site detected: {string.Join(", ", gamblingMatches)} - High financial risk", 
                "gambling_detected");
        }
        
        // Check for other sensitive operations
        var sensitiveMatches = SensitiveKeywords.Where(keyword => 
            host.Contains(keyword) || path.Contains(keyword) || text.Contains(keyword)).ToArray();
            
        if (sensitiveMatches.Any())
        {
            return new RuleResult(0.3, 
                $"Sensitive operations detected: {string.Join(", ", sensitiveMatches)} - Should use secure protocols", 
                "sensitive_operations");
        }

        return new RuleResult(0, "", "");
    }
}