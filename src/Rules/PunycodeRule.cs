using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

public sealed class PunycodeRule : IRule
{
    public RuleResult Evaluate((string Host, string Path, string? Text) f)
    {
        if (f.Host.Contains("xn--"))
            return new RuleResult(0.4, "Domain sử dụng punycode (giả mạo ký tự)", "punycode");
        return new RuleResult(0, "", "");
    }
}