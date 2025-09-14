using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

public sealed class HyphenDigitsRule : IRule
{
    static readonly Regex ManyHyphens = new(@"-.*-.*-", RegexOptions.Compiled); // >= 3 dấu '-'
    static readonly Regex DigitRun = new(@"\d{3,}", RegexOptions.Compiled);   // 3+ số liền nhau

    public RuleResult Evaluate((string Host, string Path, string? Text) f)
    {
        var host = f.Host.ToLowerInvariant();
        double s = 0; string? reason = null; string tag = "lexical_host";

        if (ManyHyphens.IsMatch(host)) { s += 0.2; reason = "Hostname có nhiều dấu '-' bất thường"; }
        if (DigitRun.IsMatch(host)) { s += 0.15; reason = reason is null ? "Hostname chứa cụm số dài" : $"{reason}; cụm số dài"; }

        return s > 0 ? new RuleResult(s, reason!, tag) : new RuleResult(0, "", "");
    }
}
