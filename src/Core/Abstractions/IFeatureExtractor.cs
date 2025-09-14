using System;
using System.Collections.Generic;
using System.Text;
using PhishRadar.Core.Models;

namespace PhishRadar.Core.Abstractions;

public interface IFeatureExtractor
{
    // Legacy method for backward compatibility
    (string Host, string Path, string? Text) Extract(ScanRequest req);
    
    // Advanced method for comprehensive feature extraction
    AdvancedFeatures ExtractAdvanced(ScanRequest req);
}