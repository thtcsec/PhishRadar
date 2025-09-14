const $ = (s) => document.querySelector(s);

document.addEventListener("DOMContentLoaded", async () => {
  const contentDiv = $("#content");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (tab?.url && tab.url.startsWith("http")) {
      // Send a message to the content script to get the last score
      const response = await chrome.tabs.sendMessage(tab.id, { action: "getLastScore" });
      
      if (response) {
        renderResult(response);
      } else {
        contentDiv.innerHTML = '<div class="loader">Không có dữ liệu cho trang này. Hãy thử làm mới lại trang.</div>';
      }
    } else {
      contentDiv.innerHTML = '<div class="loader">Không thể phân tích các trang nội bộ của trình duyệt.</div>';
    }
  } catch (e) {
    console.error("PhishRadar Popup Error:", e);
    contentDiv.innerHTML = `<div class="loader">Lỗi: ${e.message}. API có đang chạy không?</div>`;
  }
});

function renderResult(data) {
  const contentDiv = $("#content");
  const risk = data.risk ?? 0;
  const reasons = data.reasons || [];
  const recommendations = data.recommendations || [];
  const threatType = data.intelligence?.threatType || "Unknown";

  let riskLevel, riskColorClass, riskBgClass;

  if (risk >= 80) {
    riskLevel = "Rất Nguy Hiểm";
    riskColorClass = "risk-color-high";
    riskBgClass = "risk-bg-high";
  } else if (risk >= 60) {
    riskLevel = "Nguy Hiểm";
    riskColorClass = "risk-color-medium";
    riskBgClass = "risk-bg-medium";
  } else if (risk >= 20) {
    riskLevel = "Cảnh Báo";
    riskColorClass = "risk-color-low";
    riskBgClass = "risk-bg-low";
  } else {
    riskLevel = "An Toàn";
    riskColorClass = "risk-color-safe";
    riskBgClass = "risk-bg-safe";
  }

  let reasonsHtml = '<div class="details-section"><h2>Lý do</h2><ul class="details-list">' +
                    reasons.map(r => `<li><span class="icon">⚠️</span> ${r}</li>`).join('') +
                    '</ul></div>';
  if (reasons.length === 0) {
    reasonsHtml = '<div class="details-section"><h2>Lý do</h2><ul class="details-list"><li><span class="icon">✅</span> Không tìm thấy yếu tố rủi ro.</li></ul></div>';
  }

  let recommendationsHtml = '';
  if (recommendations.length > 0) {
      recommendationsHtml = '<div class="details-section"><h2>Khuyến nghị</h2><ul class="details-list">' +
                          recommendations.map(r => `<li><span class="icon">🛡️</span> ${r}</li>`).join('') +
                          '</ul></div>';
  }

  contentDiv.innerHTML = `
    <div class="results-card">
      <div class="risk-display">
        <h2 class="risk-score ${riskColorClass}">${risk}</h2>
        <p class="risk-level ${riskColorClass}">${riskLevel}</p>
        <span class="threat-type ${riskBgClass}">${threatType}</span>
      </div>
      ${reasonsHtml}
      ${recommendationsHtml}
    </div>
  `;
}
