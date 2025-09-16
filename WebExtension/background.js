const API = "http://localhost:5122";
const THRESHOLD = 80;

// Escape HTML to prevent XSS
const esc = s => String(s).replace(/[&<>"'`]/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'}[c]));

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.transitionType === "reload") return;
  const tabId = details.tabId;
  const url = details.url || "";

  if (!/^https?:/i.test(url)) return;

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 5000);
    const res = await fetch(`${API}/score`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url, text: "nav-commit" }),
      signal: ctrl.signal
    });
    clearTimeout(t);
    if (!res.ok) return;
    const data = await res.json();

    if ((data?.risk ?? 0) >= THRESHOLD) {
      // chèn overlay cảnh báo ngay
      await chrome.scripting.executeScript({
        target: { tabId },
        func: (result) => {
          const id = "phishradar-hardblock";
          if (document.getElementById(id)) return;
          const div = document.createElement("div");
          div.id = id;
          div.style.cssText = `
            position: fixed; inset: 0; z-index: 2147483647; 
            background: rgba(0,0,0,.6); display: flex; align-items: center; justify-content: center;
            font: 600 16px system-ui; color: #fff; text-align: left; padding: 24px;
          `;
          div.innerHTML = `
            <div style="max-width:720px;background:#b71c1c;padding:18px 20px;border-radius:12px;box-shadow:0 6px 24px rgba(0,0,0,.3)">
              <div style="font-size:18px;margin-bottom:8px">⚠️ PhishRadar cảnh báo: ${result.risk}%</div>
              <div style="opacity:.95;line-height:1.5;margin-bottom:12px">
                ${(result.reasons||[]).map(r=>`• ${esc(r)}`).join("<br>") || "Không có lý do cụ thể."}
              </div>
              <div style="display:flex;gap:8px;justify-content:flex-end">
                <button id="pr-continue" style="all:unset;background:#fff;color:#000;padding:8px 12px;border-radius:8px;cursor:pointer;">Vẫn truy cập</button>
                <button id="pr-leave" style="all:unset;background:#212121;color:#fff;padding:8px 12px;border-radius:8px;cursor:pointer;">Rời trang</button>
              </div>
            </div>`;
          document.documentElement.appendChild(div);
          document.getElementById("pr-leave").onclick = () => history.back();
          document.getElementById("pr-continue").onclick = () => div.remove();
        },
        args: [data]
      });
    }
  } catch {}
});
