using System.Threading.Tasks;

namespace PhishRadar.Core.Abstractions;

public interface ILogoDetectorService
{
    Task<(string? MatchedBrand, double Similarity)> CheckVisualSimilarityAsync(string url, string? htmlContent);
}
