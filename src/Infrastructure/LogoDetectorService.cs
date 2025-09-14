
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using AngleSharp;
using AngleSharp.Dom;
using Microsoft.AspNetCore.Hosting;
using PhishRadar.Core.Abstractions;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Processing;
using SixLabors.ImageSharp.PixelFormats;

namespace PhishRadar.Infrastructure;

public sealed class LogoDetectorService : ILogoDetectorService
{
    private const int HashSize = 8; // 8x8 hash -> 64 bits
    private const double SimilarityThreshold = 0.90; // 90% similarity

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IReadOnlyDictionary<string, ulong> _knownLogoHashes;

    public LogoDetectorService(IWebHostEnvironment env, IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
        var logoLibraryPath = Path.Combine(env.ContentRootPath, "LogoLibrary");
        _knownLogoHashes = PreloadLogoHashes(logoLibraryPath);
    }

    private Dictionary<string, ulong> PreloadLogoHashes(string directoryPath)
    {
        var hashes = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
        if (!Directory.Exists(directoryPath))
        {
            return hashes;
        }

        foreach (var filePath in Directory.GetFiles(directoryPath, "*.png"))
        {
            try
            {
                var brandName = Path.GetFileNameWithoutExtension(filePath);
                using var image = Image.Load(filePath);
                var hash = CalculateAverageHash(image);
                hashes[brandName] = hash;
            }
            catch { /* Ignore invalid images */ }
        }
        return hashes;
    }

    public async Task<(string? MatchedBrand, double Similarity)> CheckVisualSimilarityAsync(string url, string? htmlContent)
    {
        if (string.IsNullOrWhiteSpace(htmlContent))
        {
            try
            {
                var client = _httpClientFactory.CreateClient();
                htmlContent = await client.GetStringAsync(url);
            }
            catch
            {
                return (null, 0);
            }
        }

        var imageUrls = await GetImageUrlsFromHtml(htmlContent, url);
        var clientForImages = _httpClientFactory.CreateClient();

        foreach (var imageUrl in imageUrls)
        {
            try
            {
                await using var stream = await clientForImages.GetStreamAsync(imageUrl);
                using var image = Image.Load(stream);
                var hash = CalculateAverageHash(image);

                foreach (var (brand, knownHash) in _knownLogoHashes)
                {
                    var similarity = CompareHashes(hash, knownHash);
                    if (similarity >= SimilarityThreshold)
                    {
                        return (brand, similarity);
                    }
                }
            }
            catch { /* Ignore images that fail to download or process */ }
        }

        return (null, 0);
    }

    private async Task<IEnumerable<string>> GetImageUrlsFromHtml(string htmlContent, string baseUrl)
    {
        var context = BrowsingContext.New(AngleSharp.Configuration.Default);
        var document = await context.OpenAsync(req => req.Content(htmlContent));
        var baseUri = new Uri(baseUrl);

        var faviconUrls = document.QuerySelectorAll("link[rel='icon'], link[rel='shortcut icon']")
            .Select(l => l.GetAttribute("href"))
            .Where(h => !string.IsNullOrWhiteSpace(h));

        var logoImageUrls = document.QuerySelectorAll("img")
            .Where(img => (img.Id?.Contains("logo", StringComparison.OrdinalIgnoreCase) ?? false) ||
                          (img.ClassName?.Contains("logo", StringComparison.OrdinalIgnoreCase) ?? false) ||
                          (img.GetAttribute("src")?.Contains("logo", StringComparison.OrdinalIgnoreCase) ?? false))
            .Select(img => img.GetAttribute("src"))
            .Where(s => !string.IsNullOrWhiteSpace(s));
            
        return faviconUrls.Concat(logoImageUrls)
                          .Select(url => new Uri(baseUri, url).ToString())
                          .Distinct()
                          .Take(5); // Limit to 5 potential logos to avoid abuse
    }

    private ulong CalculateAverageHash(Image image)
    {
        // 1. Resize and convert to 8-bit grayscale
        using var processedImage = image.CloneAs<L8>();
        processedImage.Mutate(ctx => ctx.Resize(HashSize, HashSize));

        // 2. Calculate average pixel value
        long totalPixelValue = 0;
        for (int y = 0; y < processedImage.Height; y++)
        {
            for (int x = 0; x < processedImage.Width; x++)
            {
                totalPixelValue += processedImage[x, y].PackedValue;
            }
        }
        var average = (byte)(totalPixelValue / (HashSize * HashSize));

        // 3. Build the hash
        ulong hash = 0;
        ulong bitPosition = 1UL << 63;
        for (int y = 0; y < processedImage.Height; y++)
        {
            for (int x = 0; x < processedImage.Width; x++)
            {
                if (processedImage[x, y].PackedValue >= average)
                {
                    hash |= bitPosition;
                }
                bitPosition >>= 1;
            }
        }
        return hash;
    }

    private double CompareHashes(ulong hash1, ulong hash2)
    {
        // Calculate Hamming distance (number of differing bits)
        var xor = hash1 ^ hash2;
        int distance = 0;
        while (xor > 0)
        {
            distance += (int)(xor & 1);
            xor >>= 1;
        }
        
        // Return similarity percentage
        return 1.0 - ((double)distance / (HashSize * HashSize));
    }
}
