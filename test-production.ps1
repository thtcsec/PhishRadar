# PhishRadar Production Testing Suite
# Comprehensive testing for locked configuration

$apiBase = "http://localhost:5122"

# Test Vietnamese banking phishing scenarios
function Test-VietnameseBankingPhishing {
    Write-Host "🏦 TESTING VIETNAMESE BANKING PHISHING" -ForegroundColor Red
    Write-Host "=====================================" -ForegroundColor Red
    
    $testCases = @(
        @{ url = "http://fake-vietcombank.tk/login"; expected = 65; desc = "HTTP fake vietcombank" },
        @{ url = "https://vietcombank-security.ml/otp"; expected = 70; desc = "HTTPS suspicious TLD" },
        @{ url = "http://xn--vietcmbank-8za5b.com/verify"; expected = 75; desc = "Punycode + HTTP" },
        @{ url = "https://techcombank-update.xyz/xac-thuc"; expected = 70; desc = "Brand + suspicious TLD" }
    )
    
    foreach ($case in $testCases) {
        Test-SingleUrl -Url $case.url -ExpectedMin $case.expected -Description $case.desc
    }
}

# Test gambling sites
function Test-GamblingSites {
    Write-Host "`n🎰 TESTING GAMBLING SITES" -ForegroundColor Yellow
    Write-Host "=========================" -ForegroundColor Yellow
    
    $testCases = @(
        @{ url = "http://casino-bet.tk"; expected = 55; desc = "HTTP casino" },
        @{ url = "https://188bet-vietnam.com"; expected = 60; desc = "Vietnamese gambling brand" },
        @{ url = "http://cado-bongda.net"; expected = 55; desc = "Vietnamese gambling terms" },
        @{ url = "https://fun88-official.xyz"; expected = 65; desc = "Known gambling + suspicious TLD" }
    )
    
    foreach ($case in $testCases) {
        Test-SingleUrl -Url $case.url -ExpectedMin $case.expected -Description $case.desc
    }
}

# Test legitimate Vietnamese sites (should be 0% risk)
function Test-LegitimateVietnameseSites {
    Write-Host "`n✅ TESTING LEGITIMATE VIETNAMESE SITES" -ForegroundColor Green
    Write-Host "======================================" -ForegroundColor Green
    
    $testCases = @(
        @{ url = "https://vietcombank.com.vn"; expected = 0; desc = "Official Vietcombank" },
        @{ url = "https://courses.huflit.edu.vn/login/index.php"; expected = 0; desc = "HUFLIT education" },
        @{ url = "https://portal.hcmus.edu.vn"; expected = 0; desc = "HCMUS education" },
        @{ url = "https://baochinhphu.vn"; expected = 0; desc = "Government news" },
        @{ url = "https://vnexpress.net"; expected = 0; desc = "Major news site" }
    )
    
    foreach ($case in $testCases) {
        Test-SingleUrl -Url $case.url -ExpectedMax $case.expected -Description $case.desc
    }
}

# Test HTTP security penalties
function Test-HttpSecurityPenalties {
    Write-Host "`n🔓 TESTING HTTP SECURITY PENALTIES" -ForegroundColor Magenta
    Write-Host "==================================" -ForegroundColor Magenta
    
    $testCases = @(
        @{ url = "http://bank-login.tk"; expected = 45; desc = "HTTP sensitive operations" },
        @{ url = "http://verify-account.ml"; expected = 35; desc = "HTTP with verification" },
        @{ url = "http://secure-payment.xyz"; expected = 40; desc = "HTTP payment terms" }
    )
    
    foreach ($case in $testCases) {
        Test-SingleUrl -Url $case.url -ExpectedMin $case.expected -Description $case.desc
    }
}

# Single URL test function
function Test-SingleUrl {
    param(
        [string]$Url,
        [int]$ExpectedMin = 0,
        [int]$ExpectedMax = 100,
        [string]$Description
    )
    
    try {
        $body = @{ 
            url = $Url
            html = "<html><body><form action='/login'><input type='password' name='pass'/></form></body></html>"
            text = "Xác thực tài khoản ngân hàng OTP"
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$apiBase/score" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 10
        
        $passed = $true
        if ($ExpectedMin -gt 0 -and $response.risk -lt $ExpectedMin) { $passed = $false }
        if ($ExpectedMax -lt 100 -and $response.risk -gt $ExpectedMax) { $passed = $false }
        
        $statusColor = if ($passed) { "Green" } else { "Red" }
        $status = if ($passed) { "✅ PASS" } else { "❌ FAIL" }
        
        Write-Host "  $status`: $Description" -ForegroundColor $statusColor
        Write-Host "    URL: $Url" -ForegroundColor Gray
        Write-Host "    Risk: $($response.risk)% (Expected: $ExpectedMin-$ExpectedMax%)" -ForegroundColor Gray
        Write-Host "    Type: $($response.intelligence.threatType)" -ForegroundColor Gray
        Write-Host "    Rules: $($response.metrics.rulesTriggered) | ML: $([math]::Round($response.metrics.mlConfidence * 100))%" -ForegroundColor Gray
        
        if ($response.reasons.Count -gt 0) {
            Write-Host "    Reasons:" -ForegroundColor Gray
            $response.reasons | ForEach-Object { Write-Host "      • $_" -ForegroundColor DarkGray }
        }
        Write-Host ""
        
        return $passed
    }
    catch {
        Write-Host "  ❌ ERROR: $Description" -ForegroundColor Red
        Write-Host "    URL: $Url" -ForegroundColor Gray
        Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Gray
        Write-Host ""
        return $false
    }
}

# Test bulk scanning
function Test-BulkScanning {
    Write-Host "📦 TESTING BULK SCANNING" -ForegroundColor Blue
    Write-Host "========================" -ForegroundColor Blue
    
    $urls = @(
        "https://vietcombank.com.vn",
        "http://fake-vietcombank.tk", 
        "https://huflit.edu.vn",
        "http://casino-bet.ml",
        "https://google.com"
    )
    
    try {
        $body = @{ urls = $urls } | ConvertTo-Json
        $response = Invoke-RestMethod -Uri "$apiBase/bulk-scan" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 30
        
        Write-Host "  ✅ Bulk scan completed" -ForegroundColor Green
        Write-Host "  📊 Processed: $($response.processed) URLs" -ForegroundColor Gray
        
        foreach ($result in $response.results) {
            if ($result.error) {
                Write-Host "    ❌ $($result.url): $($result.error)" -ForegroundColor Red
            } else {
                Write-Host "    ✅ $($result.url): $($result.result.risk)% risk" -ForegroundColor Green
            }
        }
        Write-Host ""
    }
    catch {
        Write-Host "  ❌ Bulk scan failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
    }
}

# Test API health
function Test-ApiHealth {
    Write-Host "💚 TESTING API HEALTH" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    
    try {
        $health = Invoke-RestMethod -Uri "$apiBase/health" -Method GET -TimeoutSec 5
        Write-Host "  ✅ API Status: $($health.status)" -ForegroundColor Green
        Write-Host "  📊 Version: $($health.version)" -ForegroundColor Gray
        Write-Host "  🗄️ WHOIS Cache: $($health.features.whoisCache) entries" -ForegroundColor Gray
        Write-Host "  🔧 Advanced Features: $($health.features.advancedFeatures)" -ForegroundColor Gray
        Write-Host "  🤖 Enhanced ML: $($health.features.enhancedMl)" -ForegroundColor Gray
        Write-Host ""
    }
    catch {
        Write-Host "  ❌ Health check failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
    }
}

# Performance benchmark
function Test-Performance {
    Write-Host "⚡ PERFORMANCE BENCHMARK" -ForegroundColor Yellow
    Write-Host "=======================" -ForegroundColor Yellow
    
    $testUrl = "http://test-performance.tk"
    $iterations = 10
    $times = @()
    
    for ($i = 1; $i -le $iterations; $i++) {
        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $body = @{ url = $testUrl } | ConvertTo-Json
            $response = Invoke-RestMethod -Uri "$apiBase/score" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 5
            $stopwatch.Stop()
            
            $times += $stopwatch.ElapsedMilliseconds
            Write-Host "  Test $i`: $($stopwatch.ElapsedMilliseconds)ms" -ForegroundColor Gray
        }
        catch {
            Write-Host "  Test $i`: Failed" -ForegroundColor Red
        }
    }
    
    if ($times.Count -gt 0) {
        $avgTime = ($times | Measure-Object -Average).Average
        $maxTime = ($times | Measure-Object -Maximum).Maximum
        $minTime = ($times | Measure-Object -Minimum).Minimum
        
        Write-Host "  📊 Average: $([math]::Round($avgTime))ms" -ForegroundColor Green
        Write-Host "  📊 Min: $($minTime)ms | Max: $($maxTime)ms" -ForegroundColor Gray
        Write-Host "  🎯 Target: <200ms" -ForegroundColor $(if($avgTime -lt 200) {"Green"} else {"Red"})
    }
    Write-Host ""
}

# Main test execution
function Start-ComprehensiveTest {
    Write-Host "🛡️  PhishRadar Production Test Suite" -ForegroundColor White
    Write-Host "====================================" -ForegroundColor White
    Write-Host "Target: $apiBase" -ForegroundColor White
    Write-Host "Time: $(Get-Date)" -ForegroundColor White
    Write-Host ""
    
    # Check if API is running
    try {
        Invoke-RestMethod -Uri "$apiBase/health" -Method GET -TimeoutSec 3 | Out-Null
        Write-Host "✅ API is running" -ForegroundColor Green
        Write-Host ""
    }
    catch {
        Write-Host "❌ API is not running at $apiBase" -ForegroundColor Red
        Write-Host "Please start the API with: dotnet run --project src/Api" -ForegroundColor Yellow
        return
    }
    
    # Run all tests
    Test-ApiHealth
    Test-Performance
    Test-LegitimateVietnameseSites
    Test-VietnameseBankingPhishing
    Test-GamblingSites  
    Test-HttpSecurityPenalties
    Test-BulkScanning
    
    Write-Host "🎉 Test Suite Completed!" -ForegroundColor Green
    Write-Host "Check results above for any failures." -ForegroundColor Yellow
}

# Execute the comprehensive test
Start-ComprehensiveTest