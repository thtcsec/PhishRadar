using System;
using System.Collections.Generic;
using System.Text;

// IRuleEngine.cs
namespace PhishRadar.Core.Abstractions;
public record RuleScore(double Score, List<string> Reasons, List<string> Tags);
public interface IRuleEngine
{
    RuleScore Score((string Host, string Path, string? Text) features);
}


