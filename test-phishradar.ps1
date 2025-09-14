# PhishRadar Threat Testing Script
# Test dangerous URLs with PhishRadar API

# Base API URL (adjust if running on different port)
$apiBase = "http://localhost:5000"

# Function to test URL danger level
function Test-PhishRadarThreat {
    param(
        [string]$Url,
        [string]$Html = "",
        [string]$Text = ""
    )
    
    $body = @{
        url = $Url
        html = $Html
        text = $Text
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri "$apiBase/score" -Method POST -Body $body -ContentType "application/json"
        
        Write-Host "🔍 Testing: $Url" -ForegroundColor Cyan
        Write-Host "⚠️  Risk Score: $($response.risk)%" -ForegroundColor $(if($response.risk -gt 70) {"Red"} elseif($response.risk -gt 40) {"Yellow"} else {"Green"})
        Write-Host "📋 Reasons:" -ForegroundColor White
        $response.reasons | ForEach-Object { Write-Host "   • $_" -ForegroundColor Gray }
        Write-Host "🏷️  Tags: $($response.tags -join ', ')" -ForegroundColor Magenta
        Write-Host "─────────────────────────────────────" -ForegroundColor DarkGray
        
        return $response
    }
    catch {
        Write-Host "❌ Error testing $Url : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to test QR Code
function Test-PhishRadarQR {
    param([string]$Base64Image)
    
    $body = @{
        qrImageBase64 = $Base64Image
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri "$apiBase/score-qr" -Method POST -Body $body -ContentType "application/json"
        Write-Host "📱 QR Code Risk: $($response.risk)%" -ForegroundColor $(if($response.risk -gt 70) {"Red"} else {"Green"})
        return $response
    }
    catch {
        Write-Host "❌ QR Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to run bulk tests
function Test-BulkUrls {
    param([string[]]$Urls)
    
    $body = @{
        urls = $Urls
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri "$apiBase/bulk-scan" -Method POST -Body $body -ContentType "application/json"
    return $response
}

Write-Host "🛡️  PhishRadar Threat Testing Suite" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green

# Test Cases - Vietnamese Banking Phishing
Write-Host "`n🏦 VIETNAMESE BANKING PHISHING TESTS:" -ForegroundColor Yellow

# High-risk Vietnamese phishing URLs
$dangerousUrls = @(
    "https://vietcombank-secure.tk/otp-verify",
    "https://xn--vietcmbank-8za5b.com/login", 
    "https://techcombank-update.ml/xac-thuc",
    "https://fake-momo.xyz/verify-account",
    "https://bidv-security.club/reset-password"
)

foreach ($url in $dangerousUrls) {
    Test-PhishRadarThreat -Url $url -Text "Quý khách vui lòng xác thực OTP để mở khóa tài khoản"
}

# Test legitimate Vietnamese sites
Write-Host "`n✅ LEGITIMATE VIETNAMESE SITES:" -ForegroundColor Green
$safeUrls = @(
    "https://vietcombank.com.vn",
    "https://techcombank.com.vn", 
    "https://momo.vn",
    "https://google.com",
    "https://github.com"
)

foreach ($url in $safeUrls) {
    Test-PhishRadarThreat -Url $url
}

# Test with suspicious content
Write-Host "`n🎯 CONTENT-BASED PHISHING TESTS:" -ForegroundColor Yellow

Test-PhishRadarThreat -Url "https://suspicious-bank.com" -Text @"
Thông báo khẩn cấp!
Tài khoản của quý khách đã bị khóa do nghi vấn bảo mật.
Vui lòng truy cập link dưới đây để xác thực OTP và mở khóa:
Nhập mã OTP: ______
Số tài khoản: 1234567890
Số điện thoại: 0987654321
"@

# Test Punycode attack
Test-PhishRadarThreat -Url "https://xn--vietcmbank-8za5b.tk/verify" -Text "Vui lòng cập nhật thông tin bảo mật"

# Test bulk scanning
Write-Host "`n📦 BULK SCANNING TEST:" -ForegroundColor Yellow
$bulkUrls = @(
    "https://fake-vietcombank.tk",
    "https://legitimate-site.com.vn", 
    "https://suspicious-otp.ml"
)

$bulkResult = Test-BulkUrls -Urls $bulkUrls
Write-Host "Bulk scan completed: $($bulkResult.results.Count) URLs processed"

# Health check
Write-Host "`n💚 API HEALTH CHECK:" -ForegroundColor Green
try {
    $health = Invoke-RestMethod -Uri "$apiBase/health" -Method GET
    Write-Host "Status: $($health.status)" -ForegroundColor Green
    Write-Host "Timestamp: $($health.timestamp)"
}
catch {
    Write-Host "❌ API Health Check Failed" -ForegroundColor Red
}

# Metrics check
Write-Host "`n📊 THREAT METRICS:" -ForegroundColor Blue
try {
    $metrics = Invoke-RestMethod -Uri "$apiBase/metrics" -Method GET
    Write-Host "Total Scans Today: $($metrics.totalScansToday)"
    Write-Host "Threats Blocked: $($metrics.threatsBlocked)" -ForegroundColor Red
    Write-Host "Average Response Time: $($metrics.averageResponseTime)"
    Write-Host "Accuracy: $($metrics.accuracy)" -ForegroundColor Green
    
    Write-Host "`nTop Threats:"
    $metrics.topThreats | ForEach-Object {
        Write-Host "  • $($_.type): $($_.count)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "❌ Metrics unavailable" -ForegroundColor Red
}

Write-Host "`n🎉 Testing Complete!" -ForegroundColor Green