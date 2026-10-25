"use strict";

/* =========================================================
   BSorgu Admin Log Sistemi
   ========================================================= */

(function () {

    const ADMIN_PASS = "ArasVeBaris1";
    const LOG_KEY   = "bsorgu_logs";
    const FAIL_KEY  = "bsorgu_fail";  // { count, until }
    const BAN_KEY   = "bsorgu_ban";   // { banned: true, time }

    let cachedIP = null;

    async function getIP() {
        if (cachedIP) return cachedIP;
        try {
            const r = await fetch("https://api.ipify.org?format=json", { cache: "no-store" });
            const j = await r.json();
            cachedIP = j.ip || "bilinmiyor";
        } catch {
            cachedIP = "bilinmiyor";
        }
        return cachedIP;
    }

    function readLogs() {
        try {
            const raw = localStorage.getItem(LOG_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch { return []; }
    }
    function writeLogs(list) {
        try {
            localStorage.setItem(LOG_KEY, JSON.stringify(list));
        } catch (e) {
            console.warn("Log yazılamadı:", e);
        }
    }

    async function log(entry) {
        const ip = await getIP();
        const list = readLogs();
        list.push({
            id: Date.now() + "-" + Math.random().toString(36).slice(2, 8),
            time: new Date().toISOString(),
            ip: ip,
            type: entry.type || "bilinmiyor",
            input: entry.input || {},
            result: entry.result || null,
            url: location.href
        });
        writeLogs(list);
    }

    window.BSAdmin = {
        log: log,
        getLogs: readLogs,
        clearLogs: function () { writeLogs([]); }
    };

    function getBan() {
        try { return JSON.parse(localStorage.getItem(BAN_KEY) || "null"); }
        catch { return null; }
    }
    function setBan(flag) {
        localStorage.setItem(BAN_KEY, JSON.stringify(flag));
    }
    function getFail() {
        try { return JSON.parse(localStorage.getItem(FAIL_KEY) || '{"count":0,"until":0}'); }
        catch { return { count: 0, until: 0 }; }
    }
    function setFail(f) {
        localStorage.setItem(FAIL_KEY, JSON.stringify(f));
    }

    // 3. yanlıştan sonraki bekleme süreleri (saniye)
    const WAIT_STEPS = [60, 180, 300, 600, 3600];

    function humanWait(sec) {
        if (sec < 60) return sec + " saniye";
        if (sec < 3600) return Math.round(sec / 60) + " dakika";
        return Math.round(sec / 3600) + " saat";
    }

    const modal       = document.getElementById("adminModal");
    const openBtn     = document.getElementById("adminLoginBtn");
    const closeBtn    = document.getElementById("adminCloseBtn");
    const loginBox    = document.getElementById("adminLoginBox");
    const panelBox    = document.getElementById("adminPanelBox");
    const passInput   = document.getElementById("adminPassInput");
    const loginMsg    = document.getElementById("adminLoginMsg");
    const loginSubmit = document.getElementById("adminLoginSubmit");
    const logList     = document.getElementById("adminLogList");
    const refreshBtn  = document.getElementById("adminRefreshBtn");
    const downloadBtn = document.getElementById("adminDownloadBtn");
    const clearBtn    = document.getElementById("adminClearBtn");

    function openModal() {
        modal.style.display = "flex";
        loginBox.style.display = "block";
        panelBox.style.display = "none";
        loginMsg.textContent = "";
        passInput.value = "";
        setTimeout(function(){ passInput.focus(); }, 50);
        checkBanStatus();
    }
    function closeModal() {
        modal.style.display = "none";
    }

    if (openBtn) openBtn.addEventListener("click", openModal);
    if (closeBtn) closeBtn.addEventListener("click", closeModal);
    if (modal) modal.addEventListener("click", function(e){
        if (e.target === modal) closeModal();
    });

    let countdownTimer = null;

    function checkBanStatus() {
        if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }

        const ban = getBan();
        if (ban && ban.banned) {
            loginMsg.textContent = "🚫 IP adresiniz banlandı. Giriş yapılamaz.";
            loginSubmit.disabled = true;
            return true;
        }

        const fail = getFail();
        const now = Date.now();
        if (fail.until && fail.until > now) {
            const kalan = Math.ceil((fail.until - now) / 1000);
            loginMsg.textContent = "⏳ Bekleme süresi: " + humanWait(kalan);
            loginSubmit.disabled = true;

            countdownTimer = setInterval(function(){
                const f = getFail();
                const left = Math.ceil((f.until - Date.now()) / 1000);
                if (left <= 0) {
                    clearInterval(countdownTimer);
                    countdownTimer = null;
                    loginMsg.textContent = "";
                    loginSubmit.disabled = false;
                } else {
                    loginMsg.textContent = "⏳ Bekleme süresi: " + humanWait(left);
                }
            }, 1000);
            return true;
        }

        loginSubmit.disabled = false;
        return false;
    }

    function doLogin() {
        if (checkBanStatus()) return;

        const val = passInput.value;

        if (val === ADMIN_PASS) {
            setFail({ count: 0, until: 0 });
            loginBox.style.display = "none";
            panelBox.style.display = "block";
            renderLogs();
            return;
        }

        const fail = getFail();
        fail.count = (fail.count || 0) + 1;

        if (fail.count >= 3) {
            const idx = Math.min(fail.count - 3, WAIT_STEPS.length - 1);
            const waitSec = WAIT_STEPS[idx];
            fail.until = Date.now() + waitSec * 1000;

            if (fail.count - 3 >= WAIT_STEPS.length) {
                setBan({ banned: true, time: new Date().toISOString() });
                setFail(fail);
                loginMsg.textContent = "🚫 IP adresiniz banlandı.";
                loginSubmit.disabled = true;
                return;
            }

            setFail(fail);
            loginMsg.textContent = "❌ Yanlış şifre. " + humanWait(waitSec) + " bekleyin.";
            passInput.value = "";
            checkBanStatus();
            return;
        }

        setFail(fail);
        loginMsg.textContent = "❌ Yanlış şifre. (" + fail.count + "/3)";
        passInput.value = "";
    }

    if (loginSubmit) loginSubmit.addEventListener("click", doLogin);
    if (passInput) passInput.addEventListener("keydown", function(e){
        if (e.key === "Enter") doLogin();
    });

    function esc(s) {
        return String(s === undefined || s === null ? "-" : s)
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
    function fmtDate(iso) {
        try {
            const d = new Date(iso);
            return d.toLocaleString("tr-TR");
        } catch { return iso; }
    }

    function renderLogs() {
        const logs = readLogs();
        logList.innerHTML = "";

        if (logs.length === 0) {
            logList.innerHTML = '<div class="message info">Henüz log yok.</div>';
            return;
        }

        logs.slice().reverse().forEach(function (logItem) {
            const card = document.createElement("div");
            card.className = "result-card";
            card.style.padding = "14px";

            let inputHtml = "";
            if (logItem.input && typeof logItem.input === "object") {
                inputHtml = Object.keys(logItem.input).map(function (k) {
                    return k + ": " + esc(logItem.input[k]);
                }).join(" · ");
            }

            const resultStr = logItem.result
                ? JSON.stringify(logItem.result).slice(0, 400)
                : "-";

            card.innerHTML =
                '<div class="result-card-header" style="margin:-14px -14px 10px;padding:10px 14px;border-radius:12px 12px 0 0;">' +
                    esc(logItem.type).toUpperCase() + " · " + esc(fmtDate(logItem.time)) +
                '</div>' +
                '<div style="font-size:11px;line-height:1.8;">' +
                    '<div><b>IP:</b> ' + esc(logItem.ip) + '</div>' +
                    '<div><b>Girdi:</b> ' + esc(inputHtml || "-") + '</div>' +
                    '<div><b>Sonuç:</b> <code style="color:#8cecff;word-break:break-all;">' + esc(resultStr) + '</code></div>' +
                '</div>';

            logList.appendChild(card);
        });
    }

    if (refreshBtn) refreshBtn.addEventListener("click", renderLogs);

    if (downloadBtn) downloadBtn.addEventListener("click", function () {
        const logs = readLogs();
        const blob = new Blob([JSON.stringify(logs, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "bsorgu-logs-" + new Date().toISOString().replace(/[:.]/g, "-") + ".json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });

    if (clearBtn) clearBtn.addEventListener("click", function () {
        if (confirm("Tüm loglar silinsin mi?")) {
            writeLogs([]);
            renderLogs();
        }
    });

})();