using System;
using System.Collections.Generic;
using System.Text;
using PhishRadar.Core.Abstractions;

namespace PhishRadar.Rules;
public sealed class Featurizer : IFeaturizer
{
    public float[] Vectorize((string Host, string Path, string? Text) f)
        => new float[] { f.Host.Length, f.Path.Length, (f.Text ?? "").Length };
}