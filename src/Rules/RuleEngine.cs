using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;

/// <summary>
/// Enhanced Rule Engine với "Bộ não hợp thành" - Rules + ML Intelligence
/// Công thức: final = clamp(max(ruleScore, 0.6*ruleScore + 0.4*mlProb))
/// </summary>
public sealed class RuleEngine(IEnumerable<IRule> rules) : IRuleEngine
{
    // Legitimate Vietnamese domains whitelist
    static readonly string[] SafeVietnameseDomains = { 
        ".com.vn", ".vn", ".gov.vn", ".org.vn", ".edu.vn", ".ac.vn",
        "vietcombank.com.vn", "techcombank.com.vn", "bidv.com.vn", "acb.com.vn",
        "youtube.com", "google.com", "github.com", "microsoft.com", "facebook.com"
    };

    static readonly string[] BankBrands = { 
        "vietcombank", "vietinbank", "bidv", "techcombank", "acb", "vpbank", 
        "agribank", "vib", "mbbank", "tpbank", "sacombank", "maritimebank" 
    };

    // Enhanced phishing indicators
    static readonly string[] PhishingBait = { 
        "otp", "xác thực", "khóa tài khoản", "verify", "kích hoạt lại", "nhập mã", 
        "treo tài khoản", "mở khóa", "suspended", "expired", "urgent update",
        "tạm khóa", "bảo mật", "security alert", "verify immediately"
    };

    // Gambling indicators
    static readonly string[] GamblingIndicators = {
        "casino", "bet", "betting", "poker", "slot", "lottery", "gambling",
        "cado", "ca-do", "bongda", "keo", "188bet", "fun88", "w88", "dafabet",
        "cược", "đánh bạc", "sòng bạc", "tài xỉu", "nohu", "nổ hũ"
    };

    // Suspicious path patterns
    static readonly Regex SuspiciousPath = new(
        @"/(otp|xac-thuc|verify|reset|dang-nhap|login|update|cap-nhat|bao-mat|security|urgent)", 
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Urgency pattern detection
    static readonly Regex UrgencyPattern = new(
        @"(ngay|immediately|urgent|khẩn cấp|hết hạn|expires?|deadline|limited time)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public RuleScore Score((string Host, string Path, string? Text) f)
    {
        double score = 0; 
        var reasons = new List<string>(); 
        var tags = new List<string>();
        
        var host = f.Host.ToLowerInvariant();
        var path = f.Path.ToLowerInvariant();
        var text = (f.Text ?? "").ToLowerInvariant();
        var combinedContent = $"{host} {path} {text}";

        // ===== CONTEXT INTELLIGENCE =====

        // 1. LEGITIMATE DOMAIN CHECK (Prevent false positives)
        bool isLegitimate = IsLegitimateVietnameseDomain(host);
        if (isLegitimate)
        {
            // Legitimate domain - cap scoring at 30%
            score = 0;
            tags.Add("legitimate_domain");
            
            // Only flag if there are VERY STRONG suspicious indicators
            if (HasVeryStrongSuspiciousIndicators(combinedContent))
            {
                score = 0.2; // Low score for legitimate domains
                reasons.Add("⚠️ Legitimate domain with suspicious content");
                tags.Add("legitimate_but_suspicious");
            }
        }
        else
        {
            // ===== NON-LEGITIMATE DOMAIN ANALYSIS =====

            // 2. BANK BRAND IMPERSONATION (High Priority)
            var impersonatedBank = DetectBankImpersonation(host);
            if (!string.IsNullOrEmpty(impersonatedBank))
            {
                score += 0.7;
                reasons.Add($"🚨 BANK IMPERSONATION: Mimics '{impersonatedBank}' without legitimate domain");
                tags.Add("bank_impersonation");
            }

            // 3. GAMBLING DETECTION (High Priority for Vietnam)
            if (ContainsGamblingIndicators(combinedContent))
            {
                score += 0.6;
                reasons.Add("🎰 GAMBLING: Illegal gambling content detected");
                tags.Add("illegal_gambling");
            }

            // 4. SUSPICIOUS PATH ANALYSIS
            if (SuspiciousPath.IsMatch(path))
            {
                score += 0.3;
                reasons.Add($"⚠️ SUSPICIOUS PATH: {f.Path}");
                tags.Add("suspicious_path");
            }

            // 5. PUNYCODE ATTACK
            if (host.Contains("xn--"))
            {
                score += 0.4;
                reasons.Add("🚨 PUNYCODE: International domain attack (homoglyph)");
                tags.Add("punycode_attack");
            }

            // 6. PHISHING CONTENT ANALYSIS
            var phishingScore = AnalyzePhishingContent(text);
            if (phishingScore > 0)
            {
                score += phishingScore;
                reasons.Add($"🚨 PHISHING CONTENT: {GetPhishingDescription(phishingScore)}");
                tags.Add("phishing_content");
            }

            // 7. URGENCY + BANKING COMBINATION (Critical)
            if (UrgencyPattern.IsMatch(text) && BankBrands.Any(bank => combinedContent.Contains(bank)))
            {
                score += 0.5;
                reasons.Add("🚨 CRITICAL: Banking + Urgency combination");
                tags.Add("urgent_banking_scam");
            }

            // 8. MULTIPLE THREAT INDICATORS
            var threatCount = CountThreatIndicators(combinedContent);
            if (threatCount > 2)
            {
                score += 0.3;
                reasons.Add($"🚨 MULTI-THREAT: {threatCount} threat indicators detected");
                tags.Add("multi_threat");
            }
        }

        // ===== RULES ENGINE EVALUATION =====
        double rulesTotal = 0;
        var allRuleReasons = new List<string>();
        var allRuleTags = new List<string>();

        foreach (var rule in rules)
        {
            try
            {
                var result = rule.Evaluate(f);
                if (result.Score > 0)
                {
                    rulesTotal += result.Score;
                    if (!string.IsNullOrWhiteSpace(result.Reason)) 
                        allRuleReasons.Add($"[{rule.GetType().Name}] {result.Reason}");
                    if (!string.IsNullOrWhiteSpace(result.Tag)) 
                        allRuleTags.Add(result.Tag);
                }
            }
            catch (Exception ex)
            {
                // Log but don't fail entire evaluation
                Console.WriteLine($"[WARN] Rule {rule.GetType().Name} failed: {ex.Message}");
            }
        }

        // ===== INTELLIGENT SCORING COMBINATION =====
        var ruleScore = Math.Min(1.0, Math.Max(score, rulesTotal));

        // Context-aware adjustments for legitimate domains
        if (isLegitimate)
        {
            ruleScore = Math.Min(ruleScore, 0.3); // Cap legitimate domains at 30%
        }

        // Combine all reasons and tags
        reasons.AddRange(allRuleReasons);
        tags.AddRange(allRuleTags);

        return new RuleScore(ruleScore, reasons, tags.Distinct().ToList());
    }

    /// <summary>
    /// Combine Rules + ML with "Bộ não hợp thành" formula
    /// final = clamp(max(ruleScore, 0.6*ruleScore + 0.4*mlProb))
    /// </summary>
    public RuleScore CombineWithML(RuleScore ruleScore, double mlProbability)
    {
        var ruleScoreValue = ruleScore.Score;
        
        // "Bộ não hợp thành" formula
        var combinedScore = Math.Max(
            ruleScoreValue,                              // Pure rule score
            0.6 * ruleScoreValue + 0.4 * mlProbability  // Hybrid score
        );
        
        // Clamp final score
        var finalScore = Math.Min(1.0, Math.Max(0.0, combinedScore));
        
        // Add ML intelligence to reasons
        var enhancedReasons = new List<string>(ruleScore.Reasons);
        if (mlProbability > 0.3)
        {
            enhancedReasons.Add($"🤖 ML Intelligence: {mlProbability:F2} confidence");
        }
        
        var enhancedTags = new List<string>(ruleScore.Tags);
        if (mlProbability > 0.5)
        {
            enhancedTags.Add("ml_high_confidence");
        }
        
        return new RuleScore(finalScore, enhancedReasons, enhancedTags.Distinct().ToList());
    }

    private bool IsLegitimateVietnameseDomain(string host)
    {
        return SafeVietnameseDomains.Any(domain => host.EndsWith(domain)) ||
               IsWellKnownLegitimateService(host);
    }

    private bool IsWellKnownLegitimateService(string host)
    {
        var legitimateServices = new[]
        {
            "google.com", "youtube.com", "github.com", "microsoft.com", "facebook.com",
            "wikipedia.org", "apple.com", "amazon.com", "vnexpress.net", "dantri.com.vn",
            "tuoitre.vn", "thanhnien.vn", "vietnamnet.vn", "vtv.vn", "stackoverflow.com",
            "reddit.com", "twitter.com", "linkedin.com", "instagram.com", "tiktok.com"
        };
        
        return legitimateServices.Any(service => host.EndsWith(service));
    }

    private string DetectBankImpersonation(string host)
    {
        foreach (var bank in BankBrands)
        {
            if (host.Contains(bank) && !host.EndsWith($"{bank}.com.vn") && !host.EndsWith($"{bank}.vn"))
            {
                return bank;
            }
        }
        return string.Empty;
    }

    private bool ContainsGamblingIndicators(string content)
    {
        return GamblingIndicators.Count(indicator => content.Contains(indicator)) >= 1;
    }

    private double AnalyzePhishingContent(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return 0;

        var phishingWords = PhishingBait.Count(bait => text.Contains(bait));
        
        return phishingWords switch
        {
            >= 3 => 0.6, // High phishing density
            2 => 0.4,    // Medium phishing density  
            1 => 0.2,    // Low phishing density
            _ => 0       // No phishing indicators
        };
    }

    private string GetPhishingDescription(double score) => score switch
    {
        >= 0.5 => "High phishing keyword density",
        >= 0.3 => "Medium phishing indicators",
        _ => "Low phishing signals"
    };

    private int CountThreatIndicators(string content)
    {
        int count = 0;
        
        if (PhishingBait.Any(bait => content.Contains(bait))) count++;
        if (GamblingIndicators.Any(gambling => content.Contains(gambling))) count++;
        if (UrgencyPattern.IsMatch(content)) count++;
        if (BankBrands.Any(bank => content.Contains(bank))) count++;
        if (content.Contains("http://")) count++; // HTTP penalty
        
        return count;
    }

    private bool HasVeryStrongSuspiciousIndicators(string content)
    {
        // Very strong indicators even for legitimate domains
        var veryStrongIndicators = new[]
        {
            "click here to verify", "account will be suspended", 
            "urgent security update", "verify immediately or lose access",
            "nhấn vào đây để xác thực", "tài khoản sẽ bị khóa vĩnh viễn",
            "cập nhật ngay hoặc mất tài khoản", "xác thực trong 24h"
        };
        
        return veryStrongIndicators.Any(indicator => 
            content.Contains(indicator, StringComparison.OrdinalIgnoreCase));
    }
}