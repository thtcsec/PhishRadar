using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Infrastructure;

// This service uses a public web API (ip2whois.com) to get domain information.
// You need to sign up for a free account at https://www.ip2whois.com/ to get an API key.
public sealed class WhoisHttpService : IWhoisLookup
{
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;

    // Using IConfiguration to securely get the API key from appsettings.json
    public WhoisHttpService(HttpClient httpClient, IConfiguration configuration)
    {
        _httpClient = httpClient;
        // IMPORTANT: Get your free API key from ip2whois.com and add it to your appsettings.json
        // "Ip2WhoisApiKey": "YOUR_API_KEY_HERE"
        _apiKey = configuration["Ip2WhoisApiKey"] ?? "YOUR_API_KEY_HERE";
    }

    public async Task<int?> GetDomainAgeDaysAsync(string host, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(host) || _apiKey.Contains("YOUR_API_KEY"))
        {
            return null; // Don't run if API key is not set
        }

        try
        {
            var requestUri = $"https://api.ip2whois.com/v2?key={_apiKey}&domain={host}";
            var response = await _httpClient.GetAsync(requestUri, ct);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var json = await response.Content.ReadAsStringAsync(ct);
            var whoisData = JsonSerializer.Deserialize<Ip2WhoisResponse>(json);

            if (DateTime.TryParse(whoisData?.create_date, out var creationDate))
            {
                return (int)(DateTime.UtcNow - creationDate).TotalDays;
            }

            return null;
        }
        catch
        {
            return null; // Fail silently on any exception
        }
    }
}

// A simple record to deserialize the JSON response from the API
internal record Ip2WhoisResponse(string? create_date);