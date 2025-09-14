# Vietnamese Test Dataset for Benchmarking
# Run this to create test datasets for evaluation

# Create test data directories
New-Item -ItemType Directory -Force -Path "data"

# POSITIVE CASES (Phishing/Malicious) - Should have HIGH risk
$positives = @(
    # Vietnamese Banking Phishing
    "http://fake-vietcombank.tk/login",
    "https://vietcombank-security.ml/otp", 
    "http://techcombank-update.xyz/xac-thuc",
    "https://bidv-verify.club/account",
    "http://acb-mobile.top/signin",
    "https://vpbank-secure.click/verify",
    "http://momo-payment.tk/confirm",
    "https://zalopay-update.ml/otp",
    
    # Punycode Attacks
    "http://xn--vietcmbank-8za5b.com/login",
    "https://xn--techcmbank-7za5b.tk/verify",
    "http://xn--mm-hia.tk/payment",
    
    # Gambling Sites
    "http://casino-vietnam.tk",
    "https://188bet-official.ml", 
    "http://fun88-vn.xyz",
    "https://w88-casino.club",
    "http://cado-bongda.tk",
    "https://keo-bongda.ml",
    
    # HTTP Sensitive Operations
    "http://bank-login.tk",
    "http://secure-payment.ml",
    "http://verify-account.xyz",
    "http://otp-confirmation.club",
    
    # Logo Cloning (simulated)
    "https://vietcombank-clone.tk",
    "http://techcombank-fake.ml",
    "https://momo-phishing.xyz",
    
    # Young Domains (would be detected by WHOIS)
    "https://brand-new-bank.tk",
    "http://just-created.ml",
    
    # Cross-origin Forms
    "https://form-hijack.tk",
    "http://payment-redirect.ml",
    
    # Vietnamese Social Engineering
    "http://xac-thuc-tai-khoan.tk",
    "https://mo-khoa-ngan-hang.ml",
    "http://cap-nhat-bao-mat.xyz",
    "https://kich-hoat-the.club"
)

# NEGATIVE CASES (Legitimate) - Should have LOW/ZERO risk  
$negatives = @(
    # Official Vietnamese Banks
    "https://vietcombank.com.vn",
    "https://techcombank.com.vn",
    "https://bidv.com.vn", 
    "https://acb.com.vn",
    "https://vpbank.com.vn",
    "https://agribank.com.vn",
    "https://momo.vn",
    "https://zalopay.vn",
    "https://vnpay.vn",
    
    # Vietnamese Educational
    "https://huflit.edu.vn",
    "https://hcmus.edu.vn",
    "https://uit.edu.vn", 
    "https://hcmut.edu.vn",
    "https://ussh.edu.vn",
    "https://hust.edu.vn",
    "https://vnu.edu.vn",
    "https://courses.huflit.edu.vn/login/index.php",
    
    # Vietnamese Government
    "https://baochinhphu.vn",
    "https://vnexpress.net", 
    "https://tuoitre.vn",
    "https://thanhnien.vn",
    "https://dantri.com.vn",
    "https://vietnamnet.vn",
    
    # Global Trusted
    "https://google.com",
    "https://youtube.com",
    "https://github.com", 
    "https://microsoft.com",
    "https://facebook.com",
    "https://amazon.com",
    "https://cloudflare.com",
    "https://wikipedia.org",
    
    # Vietnamese Commerce (Legitimate)
    "https://shopee.vn",
    "https://tiki.vn",
    "https://sendo.vn",
    "https://lazada.vn",
    "https://fptshop.com.vn",
    "https://thegioididong.com"
)

# Save datasets
$positives | Out-File -FilePath "data/positives.txt" -Encoding UTF8
$negatives | Out-File -FilePath "data/negatives.txt" -Encoding UTF8

Write-Host "✅ Test datasets created:" -ForegroundColor Green
Write-Host "  📁 data/positives.txt - $($positives.Count) malicious URLs" -ForegroundColor Gray
Write-Host "  📁 data/negatives.txt - $($negatives.Count) legitimate URLs" -ForegroundColor Gray
Write-Host ""
Write-Host "🎯 Benchmark Targets:" -ForegroundColor Yellow
Write-Host "  • Positives: >70% should have risk ≥60%" -ForegroundColor Gray
Write-Host "  • Negatives: >90% should have risk ≤20%" -ForegroundColor Gray