// PhishRadar Content Script
// Vietnamese Anti-Phishing Extension

// ====== CONFIGURATION ======
const CONFIG = {
    API_BASE: "http://localhost:5122",
  RISK_THRESHOLD: 60,
  HARD_BLOCK_THRESHOLD: 80,
  API_TIMEOUT_MS: 5000,
  CONCURRENCY: 3,
  LINK_SCAN_LIMIT: 50,
  BANNER_TIMEOUT: 10000
};

// Escape HTML to prevent XSS
const esc = s => String(s).replace(/[&<>"'`]/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'}[c]));

// ====== GLOBAL STATE ======
let inflight = 0;
let lastScore = null;
let bannerInjected = false;
const linkScoreCache = new Map();

// ====== UTILITY FUNCTIONS ======

// Chuẩn hóa URL tuyệt đối, bỏ rác
function toAbsHttpUrl(href) {
  try {
    const u = new URL(href, location.href);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (u.href.startsWith(location.href + "#")) return null; // same-page anchor
    return u.href;
  } catch { 
    return null; 
  }
}

// Lấy context text ngắn quanh thẻ <a> để backend "hiểu" link này là gì
function linkContextText(a) {
  const t = (a.innerText || a.textContent || "").trim().replace(/\s+/g, " ");
  const parent = a.closest("p,li,td,div,section,article");
  const pt = parent ? (parent.innerText || "").trim().replace(/\s+/g, " ") : "";
  const ctx = [t, pt].filter(Boolean).join(" • ");
  return ctx.slice(0, 300);
}

// Kiểm tra host đáng ngờ (client-side precheck)
function looksSuspiciousHost(hostname) {
  if (!hostname) return false;
  
  const host = hostname.toLowerCase();
  
  // Vietnamese banks
  const vnBanks = ["vietcombank", "techcombank", "bidv", "acb", "vpbank", "agribank", "momo"];
  const safeTlds = [".com.vn", ".vn", ".edu.vn", ".gov.vn"];
  
  // Bank name in suspicious context
  const labels = host.split('.');
  if (vnBanks.some(bank => labels.some(label => label.includes(bank) && label !== bank)) && !safeTlds.some(tld => host.endsWith(tld))) {
    return true;
  }
  
  // Punycode
  if (host.includes("xn--")) {
    return true;
  }
  
  // Too many hyphens
  if ((host.match(/-/g) || []).length >= 3) {
    return true;
  }
  
  // Suspicious TLDs
  const suspiciousTlds = [".tk", ".ml", ".ga", ".cf", ".club", ".xyz", ".top"];
  if (suspiciousTlds.some(tld => host.endsWith(tld))) {
    return true;
  }
  
  return false;
}

// ====== UI FUNCTIONS ======

// Inject warning banner
function injectBanner(data) {
  if (bannerInjected) {
    // Update existing banner
    const existing = document.getElementById("phishradar-banner");
    if (existing) {
      updateBannerContent(existing, data);
      return;
    }
  }
  
  const banner = document.createElement("div");
  banner.id = "phishradar-banner";
  banner.style.cssText = `
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    right: 0 !important;
    background: linear-gradient(135deg, #ff4444, #cc0000) !important;
    color: white !important;
    padding: 12px 20px !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif !important;
    font-size: 14px !important;
    font-weight: bold !important;
    z-index: 2147483647 !important;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3) !important;
    border-bottom: 3px solid #990000 !important;
    animation: phishradar-slide-down 0.3s ease-out !important;
  `;
  
  updateBannerContent(banner, data);
  
  // Close button
  const closeBtn = document.createElement("button");
  closeBtn.innerHTML = "✕";
  closeBtn.style.cssText = `
    position: absolute !important;
    top: 8px !important;
    right: 15px !important;
    background: rgba(255,255,255,0.2) !important;
    border: none !important;
    color: white !important;
    font-size: 16px !important;
    font-weight: bold !important;
    width: 24px !important;
    height: 24px !important;
    border-radius: 50% !important;
    cursor: pointer !important;
  `;
  
  closeBtn.addEventListener("click", () => {
    banner.remove();
    bannerInjected = false;
  });
  
  banner.appendChild(closeBtn);
  
  // Inject CSS animation
  if (!document.getElementById("phishradar-styles")) {
    const style = document.createElement("style");
    style.id = "phishradar-styles";
    style.textContent = `
      @keyframes phishradar-slide-down {
        from { transform: translateY(-100%); }
        to { transform: translateY(0); }
      }
    `;
    document.head.appendChild(style);
  }
  
  document.body.appendChild(banner);
  bannerInjected = true;
  
  // Auto-hide after timeout
  if (data.risk < 80) {
    setTimeout(() => {
      if (banner.parentNode) {
        banner.style.animation = "phishradar-slide-down 0.3s ease-out reverse";
        setTimeout(() => {
          banner.remove();
          bannerInjected = false;
        }, 300);
      }
    }, CONFIG.BANNER_TIMEOUT);
  }
}

// Update banner content
function updateBannerContent(banner, data) {
  const risk = data.risk || 0;
  const reasons = data.reasons || [];
  const threatType = data.intelligence?.threatType || "Security Risk";
  
  let riskLevel = "AN TOÀN";
  let emoji = "✅";
  
  if (risk >= 80) { riskLevel = "RẤT NGUY HIỂM"; emoji = "🚨"; }
  else if (risk >= 60) { riskLevel = "NGUY HIỂM"; emoji = "⚠️"; }
  else if (risk >= 40) { riskLevel = "CẢNH BÁO"; emoji = "⚠️"; }
  else if (risk >= 20) { riskLevel = "CHÚ Ý"; emoji = "⚠️"; }
  
  banner.innerHTML = `
    <div style="margin-right: 30px;">
      ${emoji} <strong>PhishRadar</strong>: ${riskLevel} (${risk}%)
      <br>
      <small>🎯 ${esc(threatType)}</small>
      ${reasons.length > 0 ? `<br><small>📋 ${esc(reasons[0])}</small>` : ""}
    </div>
  `;
}

// Decorate suspicious links
function decorateLink(a, data) {
  a.classList.add("pr-link-flag");
  a.setAttribute("data-pr-risk", String(data.risk ?? 0));
  a.setAttribute("title", `⚠️ Link rủi ro ${data.risk}%: ${(data.reasons?.[0] || "Potential threat detected")}`);
  a.setAttribute("aria-label", `Cảnh báo: link rủi ro ${data.risk} phần trăm`);
  
  // Visual styling
  a.style.cssText += `
    border: 2px solid #ff9800 !important;
    background: rgba(255, 152, 0, 0.1) !important;
    border-radius: 3px !important;
    padding: 1px 3px !important;
  `;
}

// ====== ASYNC SCANNING ======

// Hàng đợi hạn mức song song
async function queueTask(task) {
  while (inflight >= CONFIG.CONCURRENCY) {
    await new Promise(r => setTimeout(r, 20));
  }
  inflight++;
  try { 
    return await task(); 
  } finally { 
    inflight--; 
  }
}

// Score single link
async function scoreOneLink(absUrl, a) {
  // Cache hit
  const cached = linkScoreCache.get(absUrl);
  if (cached) {
    if ((cached.risk ?? 0) >= CONFIG.RISK_THRESHOLD) decorateLink(a, cached);
    return;
  }

  // Timeout protection
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CONFIG.API_TIMEOUT_MS);

  try {
    const response = await fetch(`${CONFIG.API_BASE}/score`, {
      method: "POST",
      signal: ctrl.signal,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: absUrl, // Fixed: lowercase to match API
        text: linkContextText(a) || document.title
      })
    });
    
    clearTimeout(timer);
    
    if (!response.ok) return;

    const data = await response.json();
    linkScoreCache.set(absUrl, data);

    if ((data?.risk ?? 0) >= CONFIG.RISK_THRESHOLD) {
      decorateLink(a, data);
    }
  } catch (error) {
    clearTimeout(timer);
    // Silent fail for link scanning
  }
}

// Score all links on page
async function scoreLinks() {
  // Collect valid links + normalize
  const anchors = Array.from(document.querySelectorAll('a[href]'));
  const unique = [];
  const seen = new Set();

  for (const a of anchors) {
    const abs = toAbsHttpUrl(a.getAttribute("href"));
    if (!abs) continue;
    if (seen.has(abs)) continue;
    seen.add(abs);
    unique.push([abs, a]);
    if (unique.length >= CONFIG.LINK_SCAN_LIMIT) break;
  }

  if (unique.length === 0) return;

  // Use bulk scan
  const urls = unique.map(([abs]) => abs);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CONFIG.API_TIMEOUT_MS);

  try {
    const response = await fetch(`${CONFIG.API_BASE}/bulk-scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ Urls: urls }),
      signal: ctrl.signal
    });
    clearTimeout(timer);

    if (!response.ok) return;

    const { results } = await response.json();

    // Map results back to anchors
    for (let i = 0; i < results.length; i++) {
      const data = results[i];
      const [abs, a] = unique[i];
      linkScoreCache.set(abs, data);

      if ((data?.risk ?? 0) >= CONFIG.RISK_THRESHOLD) {
        decorateLink(a, data);
      }
    }
  } catch (error) {
    clearTimeout(timer);
    // Silent fail
  }
}

// ====== FORM PROTECTION ======

function hookForms() {
  // Hook all form submissions
  document.addEventListener("submit", async (e) => {
    if (!lastScore || lastScore.risk < CONFIG.HARD_BLOCK_THRESHOLD) return;
    
    const form = e.target;
    const hasPasswordField = form.querySelector('input[type="password"]');
    const hasOtpField = form.querySelector('input[name*="otp"], input[id*="otp"], input[placeholder*="otp"]');
    
    if (hasPasswordField || hasOtpField) {
      e.preventDefault();
      
      const userConfirms = confirm(`
🚨 CẢNH BÁO PHISHRADAR

Trang web này có rủi ro cao (${lastScore.risk}%)!

Lý do: ${lastScore.reasons?.[0] || "Potential phishing site detected"}

Bạn có chắc chắn muốn gửi thông tin đăng nhập?

Nhấn "Cancel" để bảo vệ tài khoản của bạn.
      `);
      
      if (userConfirms) {
        // User chose to proceed despite warning
        form.submit();
      }
    }
  }, true);
  
  if (!lastScore || lastScore.risk < CONFIG.RISK_THRESHOLD) return;

  // Highlight sensitive input fields (RED)
  const sensitiveInputs = document.querySelectorAll(`
    input[type="password"],
    input[name*="password"],
    input[name*="otp"],
    input[id*="otp"],
    input[placeholder*="otp"],
    input[name*="pin"],
    input[id*="pin"]
  `);
  
  sensitiveInputs.forEach(input => {
    input.style.cssText += `
      border: 2px solid #ff4444 !important;
      background: rgba(255, 68, 68, 0.1) !important;
    `;
  });

  // Highlight suspicious submit buttons (YELLOW)
  const submitKeywords = ["đăng nhập", "xác thực", "otp", "login", "verify"];
  const submitButtons = document.querySelectorAll('button, input[type="submit"], a[role="button"]');

  submitButtons.forEach(btn => {
    const text = (btn.innerText || btn.value || "").toLowerCase();
    if (submitKeywords.some(kw => text.includes(kw))) {
      btn.style.cssText += `
        border: 2px solid #ffc107 !important;
        background-color: rgba(255, 193, 7, 0.1) !important;
      `;
    }
  });
}

// ====== LINK HOVER SCANNING ======
let hoverTimeout = null;

function hookLinkHovers() {
  document.body.addEventListener("mouseover", (e) => {
    const a = e.target.closest("a[href]");
    if (!a) return;

    // Clear any existing timer
    clearTimeout(hoverTimeout);

    // Don't re-scan decorated links
    if (a.classList.contains("pr-link-flag")) return;

    const absUrl = toAbsHttpUrl(a.getAttribute("href"));
    if (!absUrl) return;

    // Set a new timer to scan after 300ms
    hoverTimeout = setTimeout(() => {
      if (linkScoreCache.has(absUrl)) return;
      queueTask(() => scoreOneLink(absUrl, a));
    }, 300);
  });

  document.body.addEventListener("mouseout", (e) => {
    const a = e.target.closest("a[href]");
    if (a) {
      clearTimeout(hoverTimeout);
    }
  });
}


// ====== MAIN EXECUTION ======

(async function main() {
  // Only run on HTTP/HTTPS pages
  if (!/^https?:/.test(location.href)) return;

  console.log("🛡️ PhishRadar Content Script loaded");

  // Ping API health
  try {
    await fetch(`${CONFIG.API_BASE}/health`, { method: "GET" });
  } catch {
    return; // Server not available
  }

  // 1. INSTANT WARNING - Client-side precheck
  if (looksSuspiciousHost(location.hostname)) {
    injectBanner({
      risk: 85,
      reasons: ["Host đáng ngờ (chứa tên thương hiệu, punycode, hoặc nhiều gạch ngang)"],
      intelligence: { threatType: "Suspicious Domain" }
    });
  }

  // 2. COMPREHENSIVE API ANALYSIS
  const requestBody = {
    url: location.href, // Fixed: lowercase
    html: document.documentElement.outerHTML.slice(0, 300000),
    text: document.body?.innerText?.slice(0, 20000) || document.title
  };

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), CONFIG.API_TIMEOUT_MS);
    const response = await fetch(`${CONFIG.API_BASE}/score`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody),
      signal: ctrl.signal
    });
    clearTimeout(t);

    if (response.ok) {
      const data = await response.json();
      lastScore = data;
      
      console.log("🛡️ PhishRadar analysis:", data);
      
      if ((data.risk ?? 0) >= CONFIG.RISK_THRESHOLD) {
        // Update banner with detailed API results
        injectBanner(data);
      }
    }
  } catch (error) {
    console.error("PhishRadar API call failed:", error);
    // Fail silently, instant banner might still be there
  }

  // 3. FORM & UI PROTECTION
  hookForms();

  // 4. DYNAMIC LINK SCANNING (on hover)
  hookLinkHovers();

})();

// ====== EXTENSION MESSAGING ======

// Listen for messages from popup/background
if (typeof chrome !== "undefined" && chrome.runtime) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getLastScore") {
      sendResponse(lastScore);
    } else if (request.action === "rescan") {
      main().then(() => sendResponse({ success: true }));
      return true; // Async response
    }
  });
}
