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
}
