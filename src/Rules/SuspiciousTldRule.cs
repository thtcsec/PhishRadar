using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

public sealed class SuspiciousTldRule : IRule
{
    static readonly string[] SafeTlds = { ".com.vn", ".vn", ".gov.vn", ".org.vn", ".edu.vn", ".ac.vn" };
    static readonly string[] Brands = { "vietcombank", "vietinbank", "bidv", "techcombank", "acb", "vpbank", "agribank" };

    public RuleResult Evaluate((string Host, string Path, string? Text) f)
    {
        if (Brands.Any(b => f.Host.Contains(b)) && !SafeTlds.Any(t => f.Host.EndsWith(t)))
        {
            return new RuleResult(0.55, $"Domain giống brand nhưng TLD không an toàn: {f.Host}", "typosquatting");
        }
        
        // Check for suspicious TLDs commonly used in phishing
        var suspiciousTlds = new[] { ".tk", ".ml", ".ga", ".cf", ".club", ".xyz", ".top", ".click" };
        if (suspiciousTlds.Any(tld => f.Host.EndsWith(tld)))
        {
            return new RuleResult(0.3, $"Domain sử dụng TLD đáng ngờ: {f.Host}", "suspicious_tld");
        }
        
        return new RuleResult(0, "", "");
    }
}