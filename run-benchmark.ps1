# PhishRadar Benchmark Script
# Measures the performance of the API against a local dataset.

# --- CONFIGURATION ---
$ApiBaseUrl = "http://localhost:5122"
$BulkScanEndpoint = "$ApiBaseUrl/bulk-scan"
$RiskThreshold = 70 # Risk score threshold for classifying as phishing
$PositiveFile = ".\data\positives.txt"
$NegativeFile = ".\data\negatives.txt"
$OutputFile = ".\benchmark-results.csv"

# --- SCRIPT START ---

Write-Host "🛡️ Starting PhishRadar Benchmark..."

# Function to read URLs from a file, ignoring comments and empty lines
function Get-UrlsFromFile($filePath) {
    if (-not (Test-Path $filePath)) {
        Write-Error "File not found: $filePath"
        return @()
    }
    return Get-Content $filePath | Where-Object { $_ -notmatch '^[#\s]*$' }
}

# Function to scan a list of URLs and return results
function Invoke-BulkScan($urls, $label) {
    Write-Host "- Scanning $($urls.Count) URLs for label: $label..."
    $body = @{ Urls = $urls } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri $BulkScanEndpoint -Method Post -Body $body -ContentType 'application/json'
        # The API returns results inside a 'results' property
        return $response.results | ForEach-Object {
            [PSCustomObject]@{ 
                Url = $_.url
                Label = $label
                Risk = $_.result.risk
                ThreatType = $_.result.intelligence.threatType
                Reasons = ($_.result.reasons -join ", ")
                Tags = ($_.result.tags -join ", ")
                Error = $_.error
            }
        }
    } catch {
        Write-Error "API call failed for label '$label'. Is the API running at $ApiBaseUrl?"
        Write-Error $_.Exception.Message
        return @()
    }
}

# 1. Read URLs from datasets
$positiveUrls = Get-UrlsFromFile -filePath $PositiveFile
$negativeUrls = Get-UrlsFromFile -filePath $NegativeFile

if ($positiveUrls.Count -eq 0 -or $negativeUrls.Count -eq 0) {
    Write-Error "Cannot proceed. One or both dataset files are empty or not found."
    exit
}

# 2. Run scans
$allResults = @()
$allResults += Invoke-BulkScan -urls $positiveUrls -label "positive"
$allResults += Invoke-BulkScan -urls $negativeUrls -label "negative"

# 3. Save results to CSV
$allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "- Results saved to $OutputFile" -ForegroundColor Green

# 4. Calculate and display metrics
if ($allResults.Count -gt 0) {
    # POSITIVE DATASET METRICS (Recall)
    $positives = $allResults | Where-Object { $_.Label -eq 'positive' }
    $truePositives = $positives | Where-Object { $_.Risk -ge $RiskThreshold }
    $recall = if ($positives.Count -gt 0) { $truePositives.Count / $positives.Count } else { 0 }

    # NEGATIVE DATASET METRICS (Precision / Specificity)
    $negatives = $allResults | Where-Object { $_.Label -eq 'negative' }
    $falsePositives = $negatives | Where-Object { $_.Risk -ge $RiskThreshold }
    # Precision is TP / (TP + FP), but in this context, we care more about the False Positive Rate.
    $falsePositiveRate = if ($negatives.Count -gt 0) { $falsePositives.Count / $negatives.Count } else { 0 }
    $specificity = 1 - $falsePositiveRate # How well it identifies true negatives

    Write-Host "
📊 Benchmark Metrics (Threshold >= $RiskThreshold)
" + ("-" * 40)
    Write-Host "Recall (Sensitivity) on Positive dataset: $($recall.ToString('P1')) ($($truePositives.Count)/$($positives.Count) correctly identified)"
    Write-Host "False Positive Rate on Negative dataset: $($falsePositiveRate.ToString('P1')) ($($falsePositives.Count)/$($negatives.Count) incorrectly flagged)"
    Write-Host "Specificity on Negative dataset: $($specificity.ToString('P1')) ($($negatives.Count - $falsePositives.Count)/$($negatives.Count) correctly ignored)"
    Write-Host ("-" * 40)
}

Write-Host "✅ Benchmark complete." -ForegroundColor Green
