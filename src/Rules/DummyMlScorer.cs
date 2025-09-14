using System;
using System.Collections.Generic;
using System.Text;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;
public sealed class DummyMlScorer : IMlScorer
{
    public Task<double> ScoreAsync(float[] vector, CancellationToken ct = default)
    {
        var raw = Math.Min(0.7, vector.Sum() / 300.0);
        return Task.FromResult(raw);
    }
}
