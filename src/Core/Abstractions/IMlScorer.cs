using System;
using System.Collections.Generic;
using System.Text;

namespace PhishRadar.Core.Abstractions;
public interface IMlScorer
{
    Task<double> ScoreAsync(float[] vector, CancellationToken ct = default);
}