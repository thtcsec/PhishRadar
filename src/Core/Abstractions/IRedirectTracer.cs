using System.Collections.Generic;
using System.Threading.Tasks;

namespace PhishRadar.Core.Abstractions;

public interface IRedirectTracer
{
    Task<List<string>> TraceUrlAsync(string initialUrl, CancellationToken ct = default);
}
