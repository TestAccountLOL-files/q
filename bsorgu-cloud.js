"use strict";

/* =========================================================
   BSorgu Cloud Log
   ---------------------------------------------------------
   Her sorguyu (tip, girdi, sonuc/durum) ve ziyaretci IP'sini alir,
   Cloudflare Worker'a POST eder. Admin panelde GET ile listeler,
   "TEMIZLE" butonu tum kayitlara DELETE atar.

   UYARI: Bu dosya GitHub'da herkese acik olacaktir. API anahtari
   (CF.key) tarayicidan okunabilir; yazma/silme yetkisi bu dosyaya
   baglanir. Gercek gizlilik gerekiyorsa yazmalari kendi sunucu
   tarafindan gecirmek gerekir.
   ========================================================= */

(function () {

    /* ---------------------------------------------------------
       AYARLAR
       --------------------------------------------------------- */
    var CF = {
        base: "https://bsorgu-json-depo.bsorgu.workers.dev",
        key: "shl6Ys_fs9lzR-w9ueyQYCkLj3TyQAUE"
    };

    var ADMIN_PASS = "ArasVeBaris1";
    var IP_URL = "https://api.ipify.org?format=json";

    var LOG_KEY = "bsorgu_logs";
    var FAIL_KEY = "bsorgu_fail";
    var BAN_KEY = "bsorgu_ban";

    var WAIT_STEPS = [60, 180, 300, 600, 3600];

    var $ = function (id) { return document.getElementById(id); };

    /* ---------------------------------------------------------
       YARDIMCILAR
       --------------------------------------------------------- */
    function esc(s) {
        return String(s === undefined || s === null ? "-" : s)
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    function fmtDate(iso) {
        try { return new Date(iso).toLocaleString("tr-TR"); }
        catch (e) { return iso || "-"; }
    }

    function humanWait(sec) {
        if (sec < 60) return sec + " saniye";
        if (sec < 3600) return Math.round(sec / 60) + " dakika";
        return Math.round(sec / 3600) + " saat";
    }

    /* Buyuk sonuclari kucultur: 18 bin kayitlik adsoyad cevabini
       gondermek 1 MB limitini patlatirdi. */
    function trimValue(value, depth) {
        if (value === null || value === undefined) return value;
        if (typeof value === "string") {
            return value.length > 300 ? value.slice(0, 300) + "..." : value;
        }
        if (typeof value === "number" || typeof value === "boolean") return value;
        if (depth <= 0) return "...";
        if (Array.isArray(value)) {
            var head = value.slice(0, 3).map(function (v) { return trimValue(v, depth - 1); });
            if (value.length > 3) head.push({ _kalan: value.length - 3 });
            return head;
        }
        if (typeof value === "object") {
            var out = {};
            Object.keys(value).slice(0, 30).forEach(function (k) {
                out[k] = trimValue(value[k], depth - 1);
            });
            return out;
        }
        return String(value).slice(0, 300);
    }

    /* ---------------------------------------------------------
       IP
       --------------------------------------------------------- */
    var ipPromise = null;

    function getIP() {
        if (!ipPromise) {
            ipPromise = fetch(IP_URL, { cache: "no-store" })
                .then(function (r) { return r.json(); })
                .then(function (j) { return j.ip || "bilinmiyor"; })
                .catch(function () { return "bilinmiyor"; });
        }
        return ipPromise;
    }

    /* ---------------------------------------------------------
       SORGU KAYDI (POST)
       --------------------------------------------------------- */
    function apiHeaders(withJson) {
        var h = {};
        if (withJson) h["content-type"] = "application/json";
        h["x-api-key"] = CF.key;
        return h;
    }

    function publish(entry) {
        return getIP().then(function (ip) {
            var payload = {
                sorgu: entry.sorgu || "bilinmiyor",
                ip: ip,
                zaman: new Date().toISOString(),
                girdi: entry.girdi || {},
                sonuc: trimValue(entry.sonuc, 4),
                durum: entry.durum || "basarili",
                hata: entry.hata || null,
                sayfa: location.href
            };
            return fetch(CF.base + "/api/items", {
                method: "POST",
                headers: apiHeaders(true),
                body: JSON.stringify(payload)
            });
        }).then(function (res) {
            if (!res.ok) console.warn("[cloud] kayit gonderilemedi, HTTP " + res.status);
            return res;
        }).catch(function (err) {
            console.warn("[cloud] log gonderilemedi:", err);
        });
    }

    /* Sorgu tipi ve girdisini API adresinden cikarir.
       ornek: .../proxy/adsoyad.php            -> "adsoyad"
              .../proxy/tc.php?tckn=12345678901 -> "tc" */
    function typeFromUrl(url) {
        var m = String(url).match(/\/([a-z0-9_]+)\.php/i);
        return m ? m[1] : "bilinmiyor";
    }

    function inputFromUrl(url, options) {
        var input = {};
        try {
            var u = new URL(url);
            u.searchParams.forEach(function (v, k) { input[k] = v; });
        } catch (e) { /* yoksay */ }

        if (options && typeof options.body === "string") {
            try {
                new URLSearchParams(options.body).forEach(function (v, k) {
                    if (v !== "") input[k] = v;
                });
            } catch (e) { /* yoksay */ }
        }
        return input;
    }

    /* Tum sorgular BS.fetchJson uzerinden gecer; burayi kancalayarak
       hem basarili hem hatali sorgular kaydedilir. */
    function patchFetch() {
        if (!window.BS || typeof window.BS.fetchJson !== "function") return false;
        if (window.BS.fetchJson.__cloudPatched) return true;

        var original = window.BS.fetchJson;

        var patched = async function (url, options, timeoutMs) {
            var sorgu = typeFromUrl(url);
            var girdi = inputFromUrl(url, options);
            try {
                var data = await original.call(this, url, options, timeoutMs);
                publish({ sorgu: sorgu, girdi: girdi, sonuc: data, durum: "basarili", hata: null });
                return data;
            } catch (err) {
                publish({
                    sorgu: sorgu,
                    girdi: girdi,
                    sonuc: null,
                    durum: "hata",
                    hata: err && err.name === "AbortError" ? "Zaman aşımı." : (err && err.message ? err.message : String(err))
                });
                throw err;
            }
        };

        patched.__cloudPatched = true;
        window.BS.fetchJson = patched;
        return true;
    }

    /* ---------------------------------------------------------
       ADMIN PANELI (GET / DELETE)
       --------------------------------------------------------- */
    var modal = $("adminModal");
    var openBtn = $("adminLoginBtn");
    var closeBtn = $("adminCloseBtn");
    var loginBox = $("adminLoginBox");
    var panelBox = $("adminPanelBox");
    var passInput = $("adminPassInput");
    var loginMsg = $("adminLoginMsg");
    var loginSubmit = $("adminLoginSubmit");
    var logList = $("adminLogList");
    var refreshBtn = $("adminRefreshBtn");
    var downloadBtn = $("adminDownloadBtn");
    var clearBtn = $("adminClearBtn");

    var cachedItems = [];

    function getBan() {
        try { return JSON.parse(localStorage.getItem(BAN_KEY) || "null"); }
        catch (e) { return null; }
    }
    function setBan(flag) { localStorage.setItem(BAN_KEY, JSON.stringify(flag)); }
    function getFail() {
        try { return JSON.parse(localStorage.getItem(FAIL_KEY) || '{"count":0,"until":0}'); }
        catch (e) { return { count: 0, until: 0 }; }
    }
    function setFail(f) { localStorage.setItem(FAIL_KEY, JSON.stringify(f)); }

    function openModal() {
        if (!modal) return;
        modal.style.display = "flex";
        if (loginBox) loginBox.style.display = "block";
        if (panelBox) panelBox.style.display = "none";
        if (loginMsg) loginMsg.textContent = "";
        if (passInput) passInput.value = "";
        setTimeout(function () { if (passInput) passInput.focus(); }, 50);
        checkBanStatus();
    }

    function closeModal() {
        if (modal) modal.style.display = "none";
    }

    if (openBtn) openBtn.addEventListener("click", openModal);
    if (closeBtn) closeBtn.addEventListener("click", closeModal);
    if (modal) modal.addEventListener("click", function (e) {
        if (e.target === modal) closeModal();
    });
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && modal && modal.style.display === "flex") closeModal();
    });

    var countdownTimer = null;

    function checkBanStatus() {
        if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }

        var ban = getBan();
        if (ban && ban.banned) {
            if (loginMsg) loginMsg.textContent = "🚫 IP adresiniz banlandı. Giriş yapılamaz.";
            if (loginSubmit) loginSubmit.disabled = true;
            return true;
        }

        var fail = getFail();
        var now = Date.now();
        if (fail.until && fail.until > now) {
            var kalan = Math.ceil((fail.until - now) / 1000);
            if (loginMsg) loginMsg.textContent = "⏳ Bekleme süresi: " + humanWait(kalan);
            if (loginSubmit) loginSubmit.disabled = true;

            countdownTimer = setInterval(function () {
                var f = getFail();
                var left = Math.ceil((f.until - Date.now()) / 1000);
                if (left <= 0) {
                    clearInterval(countdownTimer);
                    countdownTimer = null;
                    if (loginMsg) loginMsg.textContent = "";
                    if (loginSubmit) loginSubmit.disabled = false;
                } else if (loginMsg) {
                    loginMsg.textContent = "⏳ Bekleme süresi: " + humanWait(left);
                }
            }, 1000);
            return true;
        }

        if (loginSubmit) loginSubmit.disabled = false;
        return false;
    }

    function doLogin() {
        if (checkBanStatus()) return;

        var val = passInput ? passInput.value : "";

        if (val === ADMIN_PASS) {
            setFail({ count: 0, until: 0 });
            if (loginBox) loginBox.style.display = "none";
            if (panelBox) panelBox.style.display = "block";
            loadCloud();
            return;
        }

        var fail = getFail();
        fail.count = (fail.count || 0) + 1;

        if (fail.count >= 3) {
            var idx = Math.min(fail.count - 3, WAIT_STEPS.length - 1);
            var waitSec = WAIT_STEPS[idx];
            fail.until = Date.now() + waitSec * 1000;

            if (fail.count - 3 >= WAIT_STEPS.length) {
                setBan({ banned: true, time: new Date().toISOString() });
                setFail(fail);
                if (loginMsg) loginMsg.textContent = "🚫 IP adresiniz banlandı.";
                if (loginSubmit) loginSubmit.disabled = true;
                return;
            }

            setFail(fail);
            if (loginMsg) loginMsg.textContent = "❌ Yanlış şifre. " + humanWait(waitSec) + " bekleyin.";
            if (passInput) passInput.value = "";
            checkBanStatus();
            return;
        }

        setFail(fail);
        if (loginMsg) loginMsg.textContent = "❌ Yanlış şifre. (" + fail.count + "/3)";
        if (passInput) passInput.value = "";
    }

    if (loginSubmit) loginSubmit.addEventListener("click", doLogin);
    if (passInput) passInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") doLogin();
    });

    /* ---------- kayit kartlari ---------- */
    function renderCard(item) {
        var data = (item && item.data && typeof item.data === "object") ? item.data : {};
        var sorgu = data.sorgu || "-";
        var zaman = data.zaman || item.createdAt || item.updatedAt;
        var ip = data.ip || "-";
        var durum = data.durum || "-";

        var card = document.createElement("div");
        card.className = "result-card";
        card.style.padding = "14px";

        var inputHtml = "";
        if (data.girdi && typeof data.girdi === "object") {
            inputHtml = Object.keys(data.girdi).map(function (k) {
                return k + ": " + esc(data.girdi[k]);
            }).join(" · ");
        }

        var resultStr = "-";
        if (data.sonuc !== undefined && data.sonuc !== null) {
            try { resultStr = JSON.stringify(data.sonuc); }
            catch (e) { resultStr = String(data.sonuc); }
            if (resultStr.length > 600) resultStr = resultStr.slice(0, 600) + "…";
        }

        card.innerHTML =
            '<div class="result-card-header" style="margin:-14px -14px 10px;padding:10px 14px;border-radius:12px 12px 0 0;">' +
                esc(sorgu).toUpperCase() + " · " + esc(fmtDate(zaman)) +
            '</div>' +
            '<div style="font-size:11px;line-height:1.8;">' +
                '<div><b>IP:</b> ' + esc(ip) + '</div>' +
                '<div><b>Girdi:</b> ' + esc(inputHtml || "-") + '</div>' +
                '<div><b>Durum:</b> ' + esc(durum) +
                    (data.hata ? " · " + esc(data.hata) : "") + '</div>' +
                '<div><b>Sonuç:</b> <code style="color:#8cecff;word-break:break-all;">' + esc(resultStr) + '</code></div>' +
            '</div>';

        return card;
    }

    function renderItems(items) {
        if (!logList) return;
        logList.innerHTML = "";

        if (!items || items.length === 0) {
            logList.innerHTML = '<div class="message info">Henüz kayıt yok.</div>';
            return;
        }

        items.forEach(function (item) {
            logList.appendChild(renderCard(item));
        });
    }

    /* ---------- GET / DELETE ---------- */
    async function loadCloud() {
        if (!logList) return;
        logList.innerHTML = '<div class="message info">Yükleniyor...</div>';
        try {
            var res = await fetch(CF.base + "/", { cache: "no-store" });
            if (!res.ok) throw new Error("HTTP " + res.status);
            var items = await res.json();
            cachedItems = Array.isArray(items) ? items : [];
            renderItems(cachedItems);
        } catch (err) {
            logList.innerHTML = "";
            var box = document.createElement("div");
            box.className = "message error";
            box.textContent = "Kayıtlar alınamadı: " + err.message;
            logList.appendChild(box);
        }
    }

    async function deleteAll() {
        try {
            var res = await fetch(CF.base + "/api/items", {
                method: "DELETE",
                headers: apiHeaders(false)
            });
            if (!res.ok) throw new Error("HTTP " + res.status);
            cachedItems = [];
            await loadCloud();
        } catch (err) {
            if (logList) {
                var box = document.createElement("div");
                box.className = "message error";
                box.textContent = "Silinemedi: " + err.message;
                logList.insertBefore(box, logList.firstChild);
            }
        }
    }

    if (refreshBtn) refreshBtn.addEventListener("click", loadCloud);

    if (downloadBtn) downloadBtn.addEventListener("click", function () {
        var blob = new Blob([JSON.stringify(cachedItems, null, 2)], { type: "application/json" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = "bsorgu-logs-" + new Date().toISOString().replace(/[:.]/g, "-") + ".json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });

    if (clearBtn) clearBtn.addEventListener("click", function () {
        if (!confirm("Tüm kayıtlar silinsin mi?\nBu işlem geri alınamaz.")) return;
        deleteAll();
    });

    /* ---------------------------------------------------------
       BASLAT
       --------------------------------------------------------- */
    function start() {
        if (!patchFetch()) {
            setTimeout(function () {
                if (!patchFetch()) console.warn("[cloud] BS.fetchJson bulunamadi, kayit tutulmuyor.");
            }, 300);
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start);
    } else {
        start();
    }

    /* Dis API: bsorgu.js'in logSorgu cagrisini yakalayanlar icin. */
    window.BSCloud = {
        publish: publish,
        load: loadCloud,
        deleteAll: deleteAll,
        config: CF
    };

})();
