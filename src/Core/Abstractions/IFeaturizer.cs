using System;
using System.Collections.Generic;
using System.Text;

namespace PhishRadar.Core.Abstractions;
public interface IFeaturizer
{
    float[] Vectorize((string Host, string Path, string? Text) features);
}

