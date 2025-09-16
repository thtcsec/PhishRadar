using PhishRadar.Core.Abstractions;
using PhishRadar.Rules;
using System.Collections.Generic;
using Xunit;

public class RulesTests
{
    [Theory]
    [InlineData("xn--vitcombank-m7a.com")] // vẹrtcombank.com
    [InlineData("xn--techcombnk-hsb.com")] // techcombạnk.com
    public void PunycodeRule_Should_Flag_Punycode_Domains(string domain)
    {
        var rule = new PunycodeRule();
        var result = rule.Evaluate((domain, "/", ""));
        Assert.True(result.Score > 0);
        Assert.Equal("punycode", result.Tag);
    }

    [Theory]
    [InlineData("mybank.xyz")]
    [InlineData("secure-login.club")]
    [InlineData("account-update.top")]
    public void SuspiciousTldRule_Should_Flag_Suspicious_TLDs(string domain)
    {
        var rule = new SuspiciousTldRule();
        var result = rule.Evaluate((domain, "/", ""));
        Assert.True(result.Score > 0);
        Assert.Contains("suspicious_tld", result.Tag);
    }

    [Theory]
    [InlineData("login-mybank.com")]
    [InlineData("mybank-support.com")]
    [InlineData("verify.account.com")]
    public void HostKeywordRule_Should_Flag_Suspicious_Keywords(string domain)
    {
        var rule = new HostKeywordRule();
        var result = rule.Evaluate((domain, "/", ""));
        Assert.True(result.Score > 0);
        Assert.Equal("host_keyword", result.Tag);
    }

    [Fact]
    public void CrossOriginFormRule_Should_Flag_When_Form_Action_Is_Different_Host()
    {
        var rule = new CrossOriginFormRule();
        var html = "'''<form action='http://another-domain.com/submit'>...</form>'''";
        var result = rule.Evaluate(("current-domain.com", "/", html));
        Assert.True(result.Score > 0);
        Assert.Equal("cross_origin_form", result.Tag);
    }

    [Fact]
    public void VietnameseBankingPhishingRule_Should_Flag_Homoglyph_Bank_Name()
    {
        var rule = new VietnameseBankingPhishingRule();
        // Using a homoglyph 'vletcombank' in the host
        var result = rule.Evaluate(("vletcombank-login.com", "/", "đăng nhập tài khoản của bạn"));
        Assert.True(result.Score >= 0.8);
        Assert.Contains("vietnamese_banking_phish", result.Tag);
        Assert.Contains("typosquatting", result.Tag);
    }
    
    [Fact]
    public void EndToEnd_Test_With_RuleEngine_Should_Exceed_Threshold_For_Phishing_Url()
    {
        // ARRANGE - Setup the rule engine with all necessary rules
        var rules = new List<IRule>
        {
            new PunycodeRule(),
            new SuspiciousTldRule(),
            new HostKeywordRule(),
            new CrossOriginFormRule(),
            new VietnameseBankingPhishingRule(),
            new HttpProtocolRule()
        };
        var ruleEngine = new RuleEngine(rules);

        // ACT - Simulate a dangerous URL analysis
        var features = (
            Host: "vietcombank-login.xyz", 
            Path: "/verify/otp.php", 
            Text: "xác thực tài khoản ngân hàng vietcombank khẩn cấp, nhập mã otp"
        );
        var result = ruleEngine.Score(features);

        // ASSERT - The combined score should be high
        Assert.True(result.Score >= 0.9, $"Expected score to be >= 0.9 but was {result.Score}");
        Assert.Contains("suspicious_tld", result.Tags);
        Assert.Contains("vietnamese_banking_phish", result.Tags);
        Assert.Contains("keyword_stuffing", result.Tags);
    }

    // ===== NEW AI SEMANTIC ANALYSIS TESTS =====
    
    [Theory]
    [InlineData("vietcombank-alert.com", "/otp", "Quý khách xác thực tài khoản khẩn cấp")]
    [InlineData("secure-login.vn", "/verify", "tai khoan cua ban bi khoa, vui long xac thuc ngay")]
    [InlineData("banking-update.xyz", "/urgent", "Ngân hàng thông báo tài khoản bị đình chỉ, xác thực ngay")]
    public void AISemantic_Should_Flag_VN_Banking_Urgency(string host, string path, string text)
    {
        var rule = new AISemanticAnalysisRule();
        var result = rule.Evaluate((host, path, text));
        
        Assert.True(result.Score >= 0.6, $"Score too low: {result.Score}");
        Assert.True(result.Tags.Any(t => t.Contains("ai_semantic") || t.Contains("ai_pattern")), 
                   $"Expected AI tags, got: {string.Join(",", result.Tags)}");
        Assert.True(result.Tags.Any(t => t.Contains("banking") || t.Contains("urgency")), 
                   $"Expected banking/urgency tags, got: {string.Join(",", result.Tags)}");
    }

    [Theory]
    [InlineData("nohu-vip.club", "/", "Game bài đổi thưởng nổ hũ nhận quà")]
    [InlineData("casino-online.net", "/game", "Đánh bạc online, cá độ bóng đá")]
    [InlineData("slot-game.xyz", "/play", "no hu jackpot, doi thuong khung")]
    public void AISemantic_Should_Flag_VN_Gambling(string host, string path, string text)
    {
        var rule = new AISemanticAnalysisRule();
        var result = rule.Evaluate((host, path, text));
        
        Assert.True(result.Score >= 0.6, $"Score too low for gambling: {result.Score}");
        Assert.True(result.Tags.Any(t => t.Contains("gambling") || t.Contains("ai_semantic")), 
                   $"Expected gambling tags, got: {string.Join(",", result.Tags)}");
    }

    [Theory]
    [InlineData("crypto-invest.com", "/", "Đầu tư Bitcoin lời khủng, wallet miễn phí")]
    [InlineData("blockchain-profit.net", "/invest", "Crypto investment guaranteed profit")]
    public void AISemantic_Should_Flag_Crypto_Scam(string host, string path, string text)
    {
        var rule = new AISemanticAnalysisRule();
        var result = rule.Evaluate((host, path, text));
        
        Assert.True(result.Score >= 0.5, $"Score too low for crypto scam: {result.Score}");
        Assert.True(result.Tags.Any(t => t.Contains("crypto") || t.Contains("ai_semantic")), 
                   $"Expected crypto tags, got: {string.Join(",", result.Tags)}");
    }

    [Fact]
    public void AISemantic_Should_Handle_Mixed_Vietnamese_English()
    {
        var rule = new AISemanticAnalysisRule();
        var result = rule.Evaluate((
            "vietcombank-secure.xyz", 
            "/login/verify", 
            "Anh chị vui lòng verify account immediately, OTP expired urgent"
        ));
        
        Assert.True(result.Score >= 0.6, $"Mixed language score too low: {result.Score}");
        Assert.True(result.Tags.Any(t => t.Contains("ai_vietnamese") || t.Contains("urgency")), 
                   $"Expected Vietnamese/urgency tags, got: {string.Join(",", result.Tags)}");
    }

    [Fact] 
    public void AISemantic_Should_Handle_Normalized_Diacritics()
    {
        var rule = new AISemanticAnalysisRule();
        
        // Test with diacritics
        var resultWithDiacritics = rule.Evaluate((
            "ngân-hàng.com", "/", "Tài khoản bị khóa, xác thực khẩn cấp"
        ));
        
        // Test without diacritics (normalized)
        var resultNormalized = rule.Evaluate((
            "ngan-hang.com", "/", "Tai khoan bi khoa, xac thuc khan cap"
        ));
        
        // Both should be detected similarly
        Assert.True(resultWithDiacritics.Score >= 0.5, "Diacritics version not detected");
        Assert.True(resultNormalized.Score >= 0.5, "Normalized version not detected");
    }

    [Fact]
    public void AISemantic_Should_Not_Flag_Legitimate_Content()
    {
        var rule = new AISemanticAnalysisRule();
        var result = rule.Evaluate((
            "news.vnexpress.net", 
            "/article", 
            "Tin tức kinh tế Việt Nam, thị trường chứng khoán hôm nay"
        ));
        
        Assert.True(result.Score < 0.4, $"Legitimate content scored too high: {result.Score}");
    }

    [Fact]
    public void AISemantic_Should_Combine_Multiple_Signals()
    {
        var rule = new AISemanticAnalysisRule();
        var result = rule.Evaluate((
            "vietcombank-urgent.xyz", 
            "/verify/otp", 
            "Tài khoản ngân hàng bị khóa khẩn cấp, xác thực OTP ngay lập tức"
        ));
        
        Assert.True(result.Score >= 0.7, $"Multiple signals score too low: {result.Score}");
        
        // Check if ai_multiple_signals is in any of the tag strings
        var allTags = string.Join(",", result.Tags);
        Assert.Contains("ai_multiple_signals", allTags);
        
        // Should have multiple different signal types
        Assert.True(allTags.Contains("ai_semantic") || allTags.Contains("ai_pattern") || allTags.Contains("vietnamese"), 
                   $"Should have AI detection signals in tags: {allTags}");
    }
}
