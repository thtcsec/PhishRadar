using System;
using System.Collections.Generic;
using System.Text;
using PhishRadar.Core.Abstractions;
using PhishRadar.Core.Models;

namespace PhishRadar.Rules;

public sealed class FeatureExtractor : IFeatureExtractor
{
    public (string Host, string Path, string? Text) Extract(ScanRequest r)
    {
        string host = "", path = "";
        if (!string.IsNullOrWhiteSpace(r.Url))
        {
            var u = new Uri(r.Url);
            host = u.IdnHost.ToLowerInvariant();      // punycode-aware
            path = u.AbsolutePath.ToLowerInvariant();
        }
        var text = !string.IsNullOrWhiteSpace(r.Html) ? r.Html
                  : (r.Text ?? "");
        return (host, path, text);
    }

    public AdvancedFeatures ExtractAdvanced(ScanRequest request)
    {
        // For backward compatibility, return basic features wrapped in AdvancedFeatures
        var (host, path, text) = Extract(request);
        
        if (string.IsNullOrWhiteSpace(request.Url))
            return new AdvancedFeatures();

        try 
        {
            var uri = new Uri(request.Url);
            
            return new AdvancedFeatures
            {
                Host = host,
                Path = path,
                ContentText = text,
                Protocol = uri.Scheme,
                Port = uri.Port,
                QueryString = uri.Query,
                Fragment = uri.Fragment,
                UrlLength = request.Url.Length,
                HostLength = host.Length,
                PathLength = path.Length,
                SubdomainCount = Math.Max(0, host.Split('.').Length - 2),
                HyphenCount = host.Count(c => c == '-'),
                DigitCount = host.Count(char.IsDigit),
                HasPunycode = host.Contains("xn--"),
                TopLevelDomain = GetTopLevelDomain(host),
                NumericalFeatures = new float[] { host.Length, path.Length, (text ?? "").Length }
            };
        }
        catch (Exception)
        {
            return new AdvancedFeatures { Host = host, Path = path, ContentText = text };
        }
    }

    private string GetTopLevelDomain(string host)
    {
        var parts = host.Split('.');
        return parts.Length >= 2 ? $".{parts[^1]}" : "";
    }
}

