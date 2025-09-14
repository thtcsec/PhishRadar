using PhishRadar.Core.Abstractions;
using System.Text.RegularExpressions;

namespace PhishRadar.Rules;

/// <summary>
/// Advanced Vietnamese banking phishing detection
/// Enhanced with more comprehensive patterns and fake domains
/// </summary>
public sealed class VietnameseBankingPhishingRule : IRule
{
    private static readonly string[] VietnameseBanks = {
        "vietcombank", "vietinbank", "bidv", "techcombank", "acb", "vpbank", 
        "agribank", "vib", "mbbank", "tpbank", "sacombank", "maritimebank",
        "eximbank", "shb", "seabank", "bacabank", "namabank", "oceanbank",
        "vcb", "tcb", "vtb", "pvcombank", "kienlongbank", "gpbank"
    };

    // Common fake domain patterns for Vietnamese banks
    private static readonly string[] FakeBankPatterns = {
        "vietcom-bank", "viet-com-bank", "vietcombank-vn", "vietcombank-online",
        "techcom-bank", "tech-com-bank", "techcombank-vn", "bidv-bank",
        "acb-bank", "vpbank-vn", "agri-bank", "agribank-vn", "mb-bank",
        "vietinbank-vn", "vietin-bank", "sacom-bank", "maritime-bank"
    };

    private static readonly string[] SuspiciousKeywords = {
        // Authentication urgent
        "xác thực ngay", "xac thuc ngay", "verify immediately", "verify now",
        "tài khoản bị khóa", "tai khoan bi khoa", "account locked", "account suspended",
        "cập nhật thông tin", "cap nhat thong tin", "update information",
        
        // OTP and security
        "nhập mã otp", "nhap ma otp", "enter otp", "mã xác thực", "ma xac thuc",
        "mã pin", "ma pin", "security code", "verification code",
        
        // Urgency indicators
        "khẩn cấp", "khan cap", "urgent", "ngay lập tức", "ngay lap tuc",
        "hết hạn", "het han", "expires", "deadline", "limited time",
        
        // Phishing indicators
        "click ngay", "click here", "nhấn vào đây", "nhan vao day",
        "xác nhận ngay", "xac nhan ngay", "confirm now"
    };

    private static readonly string[] UnsafeTlds = {
        ".tk", ".ml", ".ga", ".cf", ".club", ".xyz", ".top", ".click",
        ".download", ".stream", ".science", ".racing", ".win", ".bid",
        ".loan", ".cricket", ".party", ".work", ".date"
    };

    // Vietnamese phone and account patterns
    private static readonly Regex VietnamesePhonePattern = new(@"\b(0[3-9]\d{8}|84[3-9]\d{8})\b", RegexOptions.Compiled);
    private static readonly Regex BankAccountPattern = new(@"\b\d{9,16}\b", RegexOptions.Compiled);
    private static readonly Regex FakeUrlPattern = new(@"(vietcombank|techcombank|bidv|acb|vpbank|agribank).*\.(tk|ml|ga|cf|club|xyz)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public RuleResult Evaluate((string Host, string Path, string? Text) features)
    {
        double score = 0;
        var reasons = new List<string>();
        var tags = new List<string>();

        var host = features.Host.ToLowerInvariant();
        var path = features.Path.ToLowerInvariant();
        var text = (features.Text ?? "").ToLowerInvariant();
        var normalizedText = Normalizer.RemoveDiacritics(text);

        // 1. FAKE DOMAIN PATTERNS (Highest Priority)
        foreach (var fakePattern in FakeBankPatterns)
        {
            if (host.Contains(fakePattern))
            {
                score = Math.Max(score, 0.85);
                reasons.Add($"🚨 FAKE: Vietnamese bank domain pattern '{fakePattern}'");
                tags.Add("fake_vietnamese_bank");
                break;
            }
        }

        // 2. BANK NAME + UNSAFE TLD COMBINATION
        var suspiciousBank = VietnameseBanks.FirstOrDefault(bank =>
            host.Contains(bank) && UnsafeTlds.Any(tld => host.EndsWith(tld)));

        if (suspiciousBank != null)
        {
            score = Math.Max(score, 0.9);
            reasons.Add($"🚨 CRITICAL: Vietnamese bank '{suspiciousBank}' on unsafe TLD");
            tags.Add("vietnamese_bank_unsafe_tld");
        }

        // 3. FAKE URL REGEX PATTERN
        if (FakeUrlPattern.IsMatch(host))
        {
            score = Math.Max(score, 0.85);
            reasons.Add("🚨 Bank name with suspicious TLD pattern");
            tags.Add("bank_suspicious_tld_pattern");
        }

        // 4. HOMOGLYPH & TYPOSQUATTING CHECK
        foreach (var bank in VietnameseBanks)
        {
            if (HomoglyphDetector.LooksLike(host, bank) || HomoglyphDetector.LooksLike(text, bank))
            {
                // Check if it's NOT the legitimate domain
                if (!host.EndsWith(bank + ".com.vn") && !host.EndsWith(bank + ".vn") && 
                    !host.Equals(bank + ".com") && host.Contains(bank))
                {
                    score = Math.Max(score, 0.8);
                    reasons.Add($"🎭 TYPOSQUATTING: Domain mimics '{bank}'");
                    tags.Add("vietnamese_banking_typosquatting");
                    break;
                }
            }
        }

        // 5. MULTIPLE BANKING KEYWORDS (Suspicious)
        int bankKeywordCount = VietnameseBanks.Count(bank => host.Contains(bank));
        if (bankKeywordCount > 1)
        {
            score = Math.Max(score, 0.7);
            reasons.Add($"🚨 Multiple bank names in domain ({bankKeywordCount} found)");
            tags.Add("multi_bank_impersonation");
        }

        // 6. PHISHING CONTENT ANALYSIS
        int suspiciousWordCount = SuspiciousKeywords.Count(keyword => 
            normalizedText.Contains(keyword.Replace(" ", "")));
        
        if (suspiciousWordCount >= 3)
        {
            score = Math.Max(score, 0.75);
            reasons.Add($"🚨 High phishing keyword density ({suspiciousWordCount} found)");
            tags.Add("high_phishing_density");
        }
        else if (suspiciousWordCount >= 1)
        {
            score = Math.Max(score, 0.5);
            reasons.Add($"⚠️ Phishing keywords detected ({suspiciousWordCount} found)");
            tags.Add("phishing_keywords");
        }

        // 7. SUSPICIOUS PATH PATTERNS
        if (path.Contains("otp") || path.Contains("xac-thuc") || path.Contains("verify") ||
            path.Contains("update") || path.Contains("cap-nhat") || path.Contains("login"))
        {
            score = Math.Max(score, 0.4);
            reasons.Add($"⚠️ Suspicious authentication path: {features.Path}");
            tags.Add("suspicious_auth_path");
        }

        // 8. DATA HARVESTING PATTERNS
        bool hasPhonePattern = VietnamesePhonePattern.IsMatch(text);
        bool hasBankAccount = BankAccountPattern.IsMatch(text);
        
        if (hasPhonePattern && hasBankAccount)
        {
            score = Math.Max(score, 0.6);
            reasons.Add("🚨 Phone + bank account harvesting patterns");
            tags.Add("data_harvesting");
        }
        else if (hasPhonePattern)
        {
            score = Math.Max(score, 0.3);
            reasons.Add("⚠️ Vietnamese phone number pattern detected");
            tags.Add("phone_harvesting");
        }

        // 9. VIETNAMESE CHARACTER HOMOGLYPH ATTACK
        if (ContainsVietnameseHomoglyphs(host))
        {
            score = Math.Max(score, 0.5);
            reasons.Add("🚨 Vietnamese character homoglyph attack");
            tags.Add("vietnamese_homoglyph");
        }

        // 10. LEGITIMATE DOMAIN CHECK (Reduce false positives)
        if (IsLegitimateVietnameseBankDomain(host))
        {
            score = 0;
            reasons.Clear();
            tags.Clear();
            tags.Add("legitimate_vn_bank");
        }

        return new RuleResult(Math.Min(1.0, score),
            string.Join("; ", reasons),
            string.Join(",", tags.Distinct()));
    }

    private static bool ContainsVietnameseHomoglyphs(string domain)
    {
        var suspiciousPatterns = new[] { "ă", "â", "ê", "ô", "ơ", "ư", "đ" };
        return suspiciousPatterns.Any(pattern => domain.Contains(pattern));
    }

    private static bool IsLegitimateVietnameseBankDomain(string host)
    {
        var legitimateDomains = new[]
        {
            "vietcombank.com.vn", "techcombank.com.vn", "bidv.com.vn",
            "acb.com.vn", "vpbank.com.vn", "agribank.com.vn",
            "vietinbank.vn", "mbbank.com.vn", "tpbank.com.vn",
            "sacombank.com", "maritimebank.com.vn", "eximbank.com.vn"
        };

        return legitimateDomains.Any(domain => host.EndsWith(domain));
    }
}