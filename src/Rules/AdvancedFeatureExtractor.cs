using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;
using PhishRadar.Core.Models;
using AngleSharp;
using AngleSharp.Dom;

namespace PhishRadar.Rules;

/// <summary>
/// Advanced Feature Extractor with Enhanced Intelligence
/// Extracts 25+ features for AI/ML model training
/// </summary>
public sealed class AdvancedFeatureExtractor : IFeatureExtractor
{
    // Vietnamese context patterns
    private static readonly string[] VietnameseBanks = {
        "vietcombank", "techcombank", "bidv", "acb", "vpbank", "agribank",
        "vietinbank", "mbbank", "tpbank", "sacombank", "maritimebank"
    };

    private static readonly string[] VietnamesePhishingKeywords = {
        "tài khoản", "đăng nhập", "xác thực", "ngân hàng", "chuyển khoản",
        "otp", "mã pin", "thẻ atm", "internet banking", "mobile banking"
    };

    private static readonly string[] VietnameseGamblingKeywords = {
        "cờ bạc", "đánh bạc", "casino", "nổ hũ", "tài xỉu", "cược",
        "xổ số", "lô đề", "game bài", "poker", "baccarat"
    };

    private static readonly string[] VietnameseUrgencyKeywords = {
        "khẩn cấp", "ngay lập tức", "hết hạn", "nhanh chóng", "gấp",
        "urgent", "immediately", "expires", "deadline", "asap"
    };

    private static readonly string[] SuspiciousTlds = {
        ".tk", ".ml", ".ga", ".cf", ".club", ".xyz", ".top", ".click",
        ".download", ".stream", ".science", ".racing", ".win", ".bid"
    };

    private static readonly Regex VietnamesePhonePattern = new(@"\b(0[3-9]\d{8}|84[3-9]\d{8})\b", RegexOptions.Compiled);
    private static readonly Regex SensitiveFieldPattern = new(@"(password|pin|otp|cvv|ssn|mật khẩu|mã pin)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public AdvancedFeatures ExtractAdvanced(ScanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Url))
            return new AdvancedFeatures();

        try
        {
            var uri = new Uri(request.Url);
            var host = uri.Host.ToLowerInvariant();
            var path = uri.AbsolutePath.ToLowerInvariant();
            var protocol = uri.Scheme.ToLowerInvariant();
            var html = request.Html ?? "";
            var text = request.Text ?? "";
            var combinedText = $"{request.Url} {html} {text}".ToLowerInvariant();

            // Basic URL analysis
            var basicFeatures = AnalyzeUrlStructure(request.Url, host, path, protocol);
            
            // Content analysis
            var contentFeatures = AnalyzeContent(html, text);
            
            // Vietnamese context analysis
            var vietnameseFeatures = AnalyzeVietnameseContext(combinedText, host);
            
            // Security analysis
            var securityFeatures = AnalyzeSecurity(protocol, host, html);

            return new AdvancedFeatures
            {
                // Basic URL features
                Host = host,
                Path = path,
                Protocol = protocol,
                ContentText = text.Length > 1000 ? text.Substring(0, 1000) : text,

                // URL structure
                UrlLength = basicFeatures.UrlLength,
                HostLength = basicFeatures.HostLength,
                PathLength = basicFeatures.PathLength,
                SubdomainCount = basicFeatures.SubdomainCount,
                PathDepth = basicFeatures.PathDepth,
                QueryParameterCount = basicFeatures.QueryParameterCount,
                FragmentLength = basicFeatures.FragmentLength,

                // Character analysis
                HyphenCount = basicFeatures.HyphenCount,
                DigitCount = basicFeatures.DigitCount,
                SpecialCharCount = basicFeatures.SpecialCharCount,
                UrlEntropy = basicFeatures.UrlEntropy,

                // Content features
                FormCount = contentFeatures.FormCount,
                InputFieldCount = contentFeatures.InputFieldCount,
                LinkCount = contentFeatures.LinkCount,
                ScriptCount = contentFeatures.ScriptCount,
                IframeCount = contentFeatures.IframeCount,
                HiddenFieldCount = contentFeatures.HiddenFieldCount,
                
                // Security indicators
                IsSuspiciousTld = securityFeatures.IsSuspiciousTld,
                HasPunycode = securityFeatures.HasPunycode,
                HasSensitiveFields = securityFeatures.HasSensitiveFields,
                HasRedirects = securityFeatures.HasRedirects,

                // Vietnamese context
                IsVietnameseBankDomain = vietnameseFeatures.IsVietnameseBankDomain,
                HasVietnamesePhishingKeywords = vietnameseFeatures.HasVietnamesePhishingKeywords,
                HasVietnameseGamblingKeywords = vietnameseFeatures.HasVietnameseGamblingKeywords,
                HasVietnameseUrgencyKeywords = vietnameseFeatures.HasVietnameseUrgencyKeywords,
                VietnameseThreats = vietnameseFeatures.VietnameseThreats,

                // Generate numerical features for ML
                NumericalFeatures = GenerateNumericalFeatures(basicFeatures, contentFeatures, vietnameseFeatures, securityFeatures)
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARN] Feature extraction failed for {request.Url}: {ex.Message}");
            return new AdvancedFeatures
            {
                Host = request.Url ?? "",
                Protocol = "unknown",
                NumericalFeatures = new float[24] // Default empty features
            };
        }
    }

    private UrlStructureFeatures AnalyzeUrlStructure(string url, string host, string path, string protocol)
    {
        var uri = new Uri(url);
        
        return new UrlStructureFeatures
        {
            UrlLength = url.Length,
            HostLength = host.Length,
            PathLength = path.Length,
            SubdomainCount = host.Count(c => c == '.'),
            PathDepth = path.Count(c => c == '/'),
            QueryParameterCount = uri.Query.Count(c => c == '&') + (string.IsNullOrEmpty(uri.Query) ? 0 : 1),
            FragmentLength = uri.Fragment.Length,
            HyphenCount = host.Count(c => c == '-'),
            DigitCount = host.Count(char.IsDigit),
            SpecialCharCount = url.Count(c => !char.IsLetterOrDigit(c) && c != '.' && c != '/' && c != ':'),
            UrlEntropy = CalculateEntropy(url)
        };
    }

    private ContentFeatures AnalyzeContent(string html, string text)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return new ContentFeatures
            {
                FormCount = 0,
                InputFieldCount = 0,
                LinkCount = 0,
                ScriptCount = 0,
                IframeCount = 0,
                HiddenFieldCount = 0
            };
        }

        try
        {
            // Use AngleSharp configuration without ambiguity
            var config = AngleSharp.Configuration.Default;
            var context = BrowsingContext.New(config);
            var document = context.OpenAsync(req => req.Content(html)).Result;

            var forms = document.QuerySelectorAll("form");
            var inputs = document.QuerySelectorAll("input");
            var links = document.QuerySelectorAll("a");
            var scripts = document.QuerySelectorAll("script");
            var iframes = document.QuerySelectorAll("iframe");
            var hiddenInputs = document.QuerySelectorAll("input[type='hidden']");

            return new ContentFeatures
            {
                FormCount = forms.Length,
                InputFieldCount = inputs.Length,
                LinkCount = links.Length,
                ScriptCount = scripts.Length,
                IframeCount = iframes.Length,
                HiddenFieldCount = hiddenInputs.Length
            };
        }
        catch
        {
            // Fallback to simple string parsing
            return new ContentFeatures
            {
                FormCount = CountOccurrences(html, "<form"),
                InputFieldCount = CountOccurrences(html, "<input"),
                LinkCount = CountOccurrences(html, "<a "),
                ScriptCount = CountOccurrences(html, "<script"),
                IframeCount = CountOccurrences(html, "<iframe"),
                HiddenFieldCount = CountOccurrences(html, "type=\"hidden\"") + CountOccurrences(html, "type='hidden'")
            };
        }
    }

    private VietnameseContextFeatures AnalyzeVietnameseContext(string combinedText, string host)
    {
        var threats = new List<string>();

        var isVietnameseBankDomain = VietnameseBanks.Any(bank => 
            host.Contains(bank) && !host.EndsWith($"{bank}.com.vn") && !host.EndsWith($"{bank}.vn"));

        var hasPhishingKeywords = VietnamesePhishingKeywords.Any(keyword => 
            combinedText.Contains(keyword));

        var hasGamblingKeywords = VietnameseGamblingKeywords.Any(keyword => 
            combinedText.Contains(keyword));

        var hasUrgencyKeywords = VietnameseUrgencyKeywords.Any(keyword => 
            combinedText.Contains(keyword));

        // Detect specific Vietnamese threats
        if (isVietnameseBankDomain) threats.Add("fake_vietnamese_bank");
        if (hasGamblingKeywords) threats.Add("vietnamese_gambling");
        if (hasPhishingKeywords && hasUrgencyKeywords) threats.Add("urgent_vietnamese_phishing");
        if (VietnamesePhonePattern.IsMatch(combinedText)) threats.Add("vietnamese_phone_harvesting");

        return new VietnameseContextFeatures
        {
            IsVietnameseBankDomain = isVietnameseBankDomain,
            HasVietnamesePhishingKeywords = hasPhishingKeywords,
            HasVietnameseGamblingKeywords = hasGamblingKeywords,
            HasVietnameseUrgencyKeywords = hasUrgencyKeywords,
            VietnameseThreats = threats.ToArray()
        };
    }

    private SecurityFeatures AnalyzeSecurity(string protocol, string host, string html)
    {
        var isSuspiciousTld = SuspiciousTlds.Any(tld => host.EndsWith(tld));
        var hasPunycode = host.Contains("xn--");
        var hasSensitiveFields = SensitiveFieldPattern.IsMatch(html);
        var hasRedirects = html.Contains("location.href") || html.Contains("window.location") || 
                          html.Contains("meta http-equiv=\"refresh\"");

        return new SecurityFeatures
        {
            IsSuspiciousTld = isSuspiciousTld,
            HasPunycode = hasPunycode,
            HasSensitiveFields = hasSensitiveFields,
            HasRedirects = hasRedirects
        };
    }

    private float[] GenerateNumericalFeatures(
        UrlStructureFeatures url, 
        ContentFeatures content, 
        VietnameseContextFeatures vietnamese, 
        SecurityFeatures security)
    {
        return new float[]
        {
            // Basic features (7)
            url.UrlLength,
            url.HyphenCount,
            url.DigitCount,
            url.SubdomainCount,
            url.PathDepth,
            vietnamese.HasVietnamesePhishingKeywords ? 1 : 0,
            vietnamese.IsVietnameseBankDomain ? 1 : 0,

            // Advanced structural features (7)
            url.HostLength,
            url.PathLength,
            url.QueryParameterCount,
            url.FragmentLength,
            url.SpecialCharCount,
            (float)url.UrlEntropy,
            security.IsSuspiciousTld ? 1 : 0,

            // Content features (5)
            content.FormCount,
            content.InputFieldCount,
            content.LinkCount,
            content.ScriptCount,
            content.IframeCount,

            // Security & Vietnamese features (5)
            security.HasPunycode ? 1 : 0,
            security.HasSensitiveFields ? 1 : 0,
            vietnamese.HasVietnameseGamblingKeywords ? 1 : 0,
            vietnamese.HasVietnameseUrgencyKeywords ? 1 : 0,
            vietnamese.VietnameseThreats.Length
        };
    }

    private double CalculateEntropy(string input)
    {
        if (string.IsNullOrEmpty(input)) return 0;

        var frequency = input.GroupBy(c => c).ToDictionary(g => g.Key, g => g.Count());
        var length = input.Length;
        
        return -frequency.Values.Sum(count => 
        {
            var probability = count / (double)length;
            return probability * Math.Log2(probability);
        });
    }

    private int CountOccurrences(string text, string pattern)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(pattern))
            return 0;

        int count = 0;
        int index = 0;
        while ((index = text.IndexOf(pattern, index, StringComparison.OrdinalIgnoreCase)) != -1)
        {
            count++;
            index += pattern.Length;
        }
        return count;
    }

    // Legacy method for backward compatibility
    public (string Host, string Path, string? Text) Extract(ScanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Url))
            return ("", "", request.Text);

        try
        {
            var uri = new Uri(request.Url);
            return (uri.Host, uri.AbsolutePath, request.Text);
        }
        catch
        {
            return (request.Url, "", request.Text);
        }
    }
}

// Helper classes for organizing features
internal class UrlStructureFeatures
{
    public int UrlLength { get; set; }
    public int HostLength { get; set; }
    public int PathLength { get; set; }
    public int SubdomainCount { get; set; }
    public int PathDepth { get; set; }
    public int QueryParameterCount { get; set; }
    public int FragmentLength { get; set; }
    public int HyphenCount { get; set; }
    public int DigitCount { get; set; }
    public int SpecialCharCount { get; set; }
    public double UrlEntropy { get; set; }
}

internal class ContentFeatures
{
    public int FormCount { get; set; }
    public int InputFieldCount { get; set; }
    public int LinkCount { get; set; }
    public int ScriptCount { get; set; }
    public int IframeCount { get; set; }
    public int HiddenFieldCount { get; set; }
}

internal class VietnameseContextFeatures
{
    public bool IsVietnameseBankDomain { get; set; }
    public bool HasVietnamesePhishingKeywords { get; set; }
    public bool HasVietnameseGamblingKeywords { get; set; }
    public bool HasVietnameseUrgencyKeywords { get; set; }
    public string[] VietnameseThreats { get; set; } = Array.Empty<string>();
}

internal class SecurityFeatures
{
    public bool IsSuspiciousTld { get; set; }
    public bool HasPunycode { get; set; }
    public bool HasSensitiveFields { get; set; }
    public bool HasRedirects { get; set; }
}