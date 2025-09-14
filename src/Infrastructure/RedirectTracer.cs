
using System.Collections.Generic;
using System.Net.Http;
using System.Net;
using System.Threading.Tasks;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Infrastructure;

public sealed class RedirectTracer : IRedirectTracer
{
    private readonly IHttpClientFactory _httpClientFactory;
    private const int MaxRedirects = 10;

    public RedirectTracer(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<List<string>> TraceUrlAsync(string initialUrl, CancellationToken ct = default)
    {
        var urls = new List<string> { initialUrl };
        var currentUrl = initialUrl;

        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false
        };

        using var client = new HttpClient(handler);
        client.DefaultRequestHeaders.Add("User-Agent", "PhishRadar-Bot/1.0");

        for (int i = 0; i < MaxRedirects; i++)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Head, currentUrl);
                var response = await client.SendAsync(request, ct);

                if (response.StatusCode >= HttpStatusCode.OK && response.StatusCode < HttpStatusCode.MultipleChoices)
                {
                    // Final destination
                    return urls;
                }

                if (response.StatusCode >= HttpStatusCode.MultipleChoices && response.StatusCode < HttpStatusCode.BadRequest)
                {
                    var location = response.Headers.Location;
                    if (location != null)
                    {
                        var nextUrl = location.IsAbsoluteUri ? location.ToString() : new Uri(new Uri(currentUrl), location).ToString();
                        if (!urls.Contains(nextUrl))
                        {
                            urls.Add(nextUrl);
                            currentUrl = nextUrl;
                        }
                        else
                        {
                            // Loop detected
                            return urls;
                        }
                    }
                    else
                    {
                        // No Location header
                        return urls;
                    }
                }
                else
                {
                    // Client or server error
                    return urls;
                }
            }
            catch (HttpRequestException)
            {
                // Network error or invalid URL
                return urls;
            }
        }

        return urls; // Max redirects reached
    }
}
