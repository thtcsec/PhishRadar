using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// IRule.cs
namespace PhishRadar.Core.Abstractions;
public interface IRule
{
    RuleResult Evaluate((string Host, string Path, string? Text) f);
}
public record RuleResult(double Score, string Reason, string Tag)
{
    // Convert single reason to list for compatibility
    public List<string> Reasons => string.IsNullOrWhiteSpace(Reason) ? new List<string>() : new List<string> { Reason };
    public List<string> Tags => string.IsNullOrWhiteSpace(Tag) ? new List<string>() : new List<string> { Tag };
};

