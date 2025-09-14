using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

public sealed class CrossOriginFormRule : IRule
{
    static readonly Regex FormAction = new(@"<form[^>]*\baction\s*=\s*['""]?([^'""\s>]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    public RuleResult Evaluate((string Host, string Path, string? Text) f)
    {
        // text ở đây ta tận dụng Html được đẩy qua ScanRequest.Html → đã map vào Text ở FeatureExtractor
        var html = f.Text ?? string.Empty;
        if (string.IsNullOrWhiteSpace(html)) return new RuleResult(0, "", "");

        var matches = FormAction.Matches(html);
        if (matches.Count == 0) return new RuleResult(0, "", "");

        var offDomain = 0;
        foreach (Match m in matches)
        {
            var action = m.Groups[1].Value.Trim();
            if (!action.StartsWith("http")) continue;
            try
            {
                var u = new Uri(action);
                if (!u.Host.EndsWith(f.Host, StringComparison.OrdinalIgnoreCase)
                    && !f.Host.EndsWith(u.Host, StringComparison.OrdinalIgnoreCase))
                    offDomain++;
            }
            catch { /* ignore */ }
        }
        if (offDomain > 0)
            return new RuleResult(0.3, $"Form POST sang domain khác ({offDomain} form)", "cross_origin_form");

        return new RuleResult(0, "", "");
    }
}
