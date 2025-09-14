using PhishRadar.Rules;
using Xunit;

public class RuleEngineTests
{
    [Fact]
    public void Typosquat_And_Bait_Should_Raise_Score()
    {
        var rules = new RuleEngine();
        var r = rules.Score(("vietcombank-secure-login.com", "/reset", "Quý khách xác thực OTP"));
        Assert.True(r.Score >= 0.55);                  // brand + tld lạ
        Assert.Contains(r.Tags, t => t == "typosquatting");
        Assert.Contains(r.Tags, t => t == "content_risk");
    }

    [Fact]
    public void Punycode_Should_Add_Risk()
    {
        var rules = new RuleEngine();
        var r = rules.Score(("xn--vtecombank-5za.com", "/login", ""));
        Assert.Contains(r.Tags, t => t == "punycode");
    }
}