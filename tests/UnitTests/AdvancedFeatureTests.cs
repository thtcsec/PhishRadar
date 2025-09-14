using PhishRadar.Rules;
using PhishRadar.Core.Models;
using Xunit;

namespace PhishRadar.Tests;

public class AdvancedFeatureExtractorTests
{
    [Fact]
    public void ExtractAdvanced_Should_Extract_Comprehensive_Features()
    {
        // Arrange
        var extractor = new AdvancedFeatureExtractor();
        var request = new ScanRequest
        {
            Url = "https://fake-vietcombank.tk/otp-verify?token=123",
            Html = "<html><body><form><input type='password' name='pin'/></form></body></html>",
            Text = "Xác thực OTP để mở khóa tài khoản ngân hàng"
        };

        // Act
        var features = extractor.ExtractAdvanced(request);

        // Assert
        Assert.Equal("fake-vietcombank.tk", features.Host);
        Assert.Equal("/otp-verify", features.Path);
        Assert.True(features.IsSuspiciousTld);
        Assert.True(features.IsVietnameseBankDomain);
        Assert.True(features.HasVietnamesePhishingKeywords);
        Assert.Contains("otp_phishing", features.VietnameseThreats);
        Assert.True(features.HasSensitiveFields);
        Assert.True(features.NumericalFeatures.Length >= 20);
    }

    [Fact]
    public void ExtractAdvanced_Should_Handle_Punycode_Domains()
    {
        // Arrange
        var extractor = new AdvancedFeatureExtractor();
        var request = new ScanRequest
        {
            Url = "https://xn--vietcmbank-8za5b.com/login"
        };

        // Act
        var features = extractor.ExtractAdvanced(request);

        // Assert
        Assert.True(features.HasPunycode);
        Assert.Contains("1", features.NumericalFeatures.Select(f => f.ToString())); // Punycode flag should be 1
    }

    [Fact]
    public void ExtractAdvanced_Should_Calculate_Entropy()
    {
        // Arrange
        var extractor = new AdvancedFeatureExtractor();
        var request = new ScanRequest
        {
            Url = "https://randomstring123456789.com"
        };

        // Act
        var features = extractor.ExtractAdvanced(request);

        // Assert
        Assert.True(features.EntropyScore > 0);
        Assert.True(features.EntropyScore <= 5); // Max theoretical entropy for reasonable strings
    }
}

public class EnhancedMlScorerTests
{
    [Fact]
    public async Task ScoreAdvancedAsync_Should_Boost_Vietnamese_Threats()
    {
        // Arrange
        var scorer = new EnhancedMlScorer();
        var features = new AdvancedFeatures
        {
            IsVietnameseBankDomain = true,
            IsSuspiciousTld = true,
            HasVietnamesePhishingKeywords = true,
            VietnameseThreats = new[] { "otp_phishing", "banking_impersonation", "account_suspension" },
            NumericalFeatures = new float[25] // Initialize with basic values
        };

        // Act
        var score = await scorer.ScoreAdvancedAsync(features);

        // Assert
        Assert.True(score > 0.5); // Should have high score due to Vietnamese threat indicators
        Assert.True(score <= 1.0);
    }

    [Fact]
    public async Task ScoreAsync_Should_Handle_Basic_Vectors()
    {
        // Arrange
        var scorer = new EnhancedMlScorer();
        var basicVector = new float[] { 50, 20, 100, 2, 1, 1, 1, 1 }; // Length + suspicious indicators

        // Act
        var score = await scorer.ScoreAsync(basicVector);

        // Assert
        Assert.True(score >= 0);
        Assert.True(score <= 1.0);
    }
}