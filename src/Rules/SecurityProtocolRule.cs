using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

/// <summary>
/// Security protocol rule - penalizes HTTP and other insecure practices
/// </summary>
public sealed class SecurityProtocolRule : IRule
{
    public RuleResult Evaluate((string Host, string Path, string? Text) f)
    {
        var host = f.Host.ToLowerInvariant();
        var path = f.Path.ToLowerInvariant();
        var text = (f.Text ?? "").ToLowerInvariant();
        
        double score = 0;
        var reasons = new List<string>();
        var tags = new List<string>();

        // Check for HTTP (non-HTTPS) - CRITICAL for sensitive operations
        if (ContainsSensitiveOperations(host, path, text))
        {
            score += 0.4;
            reasons.Add("Site handles sensitive operations without HTTPS encryption");
            tags.Add("http_sensitive");
        }
        
        // Check for suspicious ports
        if (host.Contains(":") && !IsStandardPort(host))
        {
            score += 0.2;
            reasons.Add("Using non-standard port - possible proxy/tunnel");
            tags.Add("suspicious_port");
        }
        
        // Check for IP addresses instead of domains
        if (IsIpAddress(host))
        {
            score += 0.3;
            reasons.Add("Using IP address instead of domain name");
            tags.Add("ip_address");
        }
        
        // Check for suspicious subdomain patterns
        if (HasSuspiciousSubdomains(host))
        {
            score += 0.25;
            reasons.Add("Suspicious subdomain pattern detected");
            tags.Add("suspicious_subdomain");
        }

        if (score > 0)
        {
            return new RuleResult(Math.Min(1.0, score), 
                string.Join("; ", reasons), 
                string.Join(",", tags));
        }

        return new RuleResult(0, "", "");
    }

    private bool ContainsSensitiveOperations(string host, string path, string text)
    {
        var sensitiveKeywords = new[] { 
            "login", "signin", "password", "otp", "verify", "bank", "payment", 
            "credit", "card", "account", "wallet", "transfer", "deposit"
        };
        
        return sensitiveKeywords.Any(keyword => 
            host.Contains(keyword) || path.Contains(keyword) || text.Contains(keyword));
    }

    private bool IsStandardPort(string host)
    {
        var standardPorts = new[] { ":80", ":443", ":8080", ":3000", ":5000" };
        return standardPorts.Any(port => host.EndsWith(port));
    }

    private bool IsIpAddress(string host)
    {
        // Simple IP address detection
        var ipPattern = @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}";
        return Regex.IsMatch(host.Split(':')[0], ipPattern);
    }

    private bool HasSuspiciousSubdomains(string host)
    {
        var suspiciousPatterns = new[] {
            "www-", "secure-", "login-", "verify-", "update-", 
            "ssl-", "https-", "account-", "bank-"
        };
        
        return suspiciousPatterns.Any(pattern => host.Contains(pattern));
    }
}