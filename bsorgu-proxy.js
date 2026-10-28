"use strict";

/* =========================================================
   BSorgu Proxy Katmani
   ---------------------------------------------------------
   Sayfa her acildiginda Worker'dan rastgele bir ABD proxy
   secilir ve TUM sorgular o proxy uzerinden gonderilir.
   Sayfa yenilendiginde yeni proxy secilir.

   Tarayici SOCKS5/HTTP proxy kullanamadigi icin yonlendirme
   Worker'da yapilir: Worker proxy'ye baglanir, hedef adresi
   absolute formda verir, cevabi oldugu gibi geri dondurur.

   Yeni adres turetilir:
     https://belsis2.world/api/proxy/tc.php?tckn=...
     -> https://<worker>/api/proxy/tc.php?tckn=...   (x-proxy basligi ile)

   Basliktaki anahtar proxy'yi kapatabilir. Kapatilirken uyari
   modali cikar; "Bir daha gösterme" secilirse uyari bir daha
   gelmez.
   ========================================================= */

(function () {

    var WORKER = "https://bsorgu-json-depo.bsorgu.workers.dev";
    var UPSTREAM = "https://belsis2.world";
    var TIMEOUT_MS = 60000;

    /* bsorgu.js'in varsayilan basliklari; upstream bunlari bekliyor. */
    var DEFAULTS = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest"
    };

    var OFF_KEY = "bsorgu_proxy_off";
    var WARN_KEY = "bsorgu_proxy_warn_once";

    var state = {
        enabled: true,
        proxy: "",
        exitIp: "",
        country: "",
        city: "",
        pickedAt: "",
        ready: null
    };

    /* ---------------------------------------------------------
       Rozet (basliktaki aktif proxy gostergesi)
       --------------------------------------------------------- */
    function paint(text, stateName) {
        var box = document.getElementById("proxyBadge");
        var label = document.getElementById("proxyText");
        if (!box || !label) return;
        label.textContent = text;
        box.className = "proxy-badge" + (stateName ? " is-" + stateName : "");
    }

    function paintProxy(data) {
        var tip = "Proxy: " + data.proxy;
        if (data.city) tip += " | " + data.city;
        if (data.exitIp) tip += " | Cikis IP: " + data.exitIp;
        var box = document.getElementById("proxyBadge");
        if (box) box.title = tip;
        paint(data.ip || data.proxy, "");
    }

    function paintOff() {
        var box = document.getElementById("proxyBadge");
        if (box) {
            box.title = "Proxy kapali. Verilerin getirilmesi icin VPN gereklidir.";
        }
        paint("PROXY KAPALI", "off");
    }

    function syncSwitch() {
        var sw = document.getElementById("proxySwitch");
        if (!sw) return;
        sw.setAttribute("aria-checked", state.enabled ? "true" : "false");
        sw.title = state.enabled ? "Proxy acik - kapatmak icin tikla" : "Proxy kapali - acmak icin tikla";
    }

    /* ---------------------------------------------------------
       Proxy secme
       --------------------------------------------------------- */
    async function doPick() {
        paint("PROXY...", "loading");
        var res = await fetch(WORKER + "/api/proxies", { cache: "no-store" });
        if (!res.ok) throw new Error("Proxy alinamadi (HTTP " + res.status + ")");
        var data = await res.json();
        if (!data || !data.proxy) {
            throw new Error((data && data.error) || "Calisan proxy bulunamadi.");
        }
        state.proxy = data.proxy;
        state.exitIp = data.exitIp || "";
        state.country = data.country || "";
        state.city = data.city || "";
        state.pickedAt = data.pickedAt || "";
        paintProxy(data);
        return data.proxy;
    }

    function ensureProxy() {
        if (!state.ready) state.ready = doPick();
        return state.ready;
    }

    function repick() {
        state.ready = doPick();
        return state.ready;
    }

    /* ---------------------------------------------------------
       Acma / kapama
       --------------------------------------------------------- */
    function clearProxyInfo() {
        state.proxy = "";
        state.exitIp = "";
        state.country = "";
        state.city = "";
        state.pickedAt = "";
        state.ready = null;
    }

    function setEnabled(on) {
        state.enabled = on;
        clearProxyInfo();
        syncSwitch();

        if (on) {
            try { localStorage.removeItem(OFF_KEY); } catch (e) { /* yoksay */ }
            repick().catch(function (err) {
                paint("PROXY YOK", "error");
                console.warn("[proxy] proxy secilemedi:", err);
            });
            return;
        }

        try { localStorage.setItem(OFF_KEY, "1"); } catch (e) { /* yoksay */ }
        paintOff();
    }

    /* ---------------------------------------------------------
       Uyari modali
       --------------------------------------------------------- */
    function openWarn() {
        var modal = document.getElementById("proxyWarnModal");
        var chk = document.getElementById("proxyWarnDontShow");
        if (chk) chk.checked = false;
        if (modal) modal.style.display = "flex";
    }

    function closeWarn() {
        var modal = document.getElementById("proxyWarnModal");
        if (modal) modal.style.display = "none";
    }

    function warnSkipped() {
        try { return localStorage.getItem(WARN_KEY) === "1"; } catch (e) { return false; }
    }

    function wireSwitch() {
        var sw = document.getElementById("proxySwitch");
        if (!sw) return;

        sw.addEventListener("click", function () {
            if (!state.enabled) {
                setEnabled(true);
                return;
            }
            if (warnSkipped()) {
                setEnabled(false);
                return;
            }
            openWarn();
        });

        var cancelBtn = document.getElementById("proxyWarnCancel");
        if (cancelBtn) cancelBtn.addEventListener("click", closeWarn);

        var confirmBtn = document.getElementById("proxyWarnConfirm");
        if (confirmBtn) {
            confirmBtn.addEventListener("click", function () {
                var chk = document.getElementById("proxyWarnDontShow");
                if (chk && chk.checked) {
                    try { localStorage.setItem(WARN_KEY, "1"); } catch (e) { /* yoksay */ }
                }
                closeWarn();
                setEnabled(false);
            });
        }

        var modal = document.getElementById("proxyWarnModal");
        if (modal) {
            modal.addEventListener("click", function (e) {
                if (e.target === modal) closeWarn();
            });
        }

        document.addEventListener("keydown", function (e) {
            var modal = document.getElementById("proxyWarnModal");
            if (e.key === "Escape" && modal && modal.style.display === "flex") closeWarn();
        });
    }

    /* ---------------------------------------------------------
       Sorgu yonlendirme
       --------------------------------------------------------- */
    function route(url) {
        if (typeof url !== "string") return url;
        if (url.indexOf(UPSTREAM) !== 0) return url;
        return WORKER + url.slice(UPSTREAM.length);
    }

    function patchFetch() {
        if (!window.BS || typeof window.BS.fetchJson !== "function") return false;
        if (window.BS.fetchJson.__proxyPatched) return true;

        var original = window.BS.fetchJson;

        var patched = async function (url, options, timeoutMs) {
            if (!state.enabled) {
                return await original.call(this, url, options, timeoutMs);
            }

            var target = route(url);
            if (target === url) {
                return await original.call(this, url, options, timeoutMs);
            }

            var opts = Object.assign({}, options || {});
            var headers = Object.assign({}, DEFAULTS, (options && options.headers) || {});
            var limit = timeoutMs || TIMEOUT_MS;

            for (var attempt = 0; attempt < 2; attempt++) {
                try {
                    headers["x-proxy"] = await ensureProxy();
                    opts.headers = headers;
                    return await original.call(this, target, opts, limit);
                } catch (err) {
                    if (attempt === 0) {
                        try {
                            await repick();
                            continue;
                        } catch (pickErr) {
                            throw err;
                        }
                    }
                    throw err;
                }
            }
        };

        patched.__proxyPatched = true;
        window.BS.fetchJson = patched;
        return true;
    }

    /* ---------------------------------------------------------
       Baslat
       --------------------------------------------------------- */
    window.BSProxy = {
        state: state,
        ensureProxy: ensureProxy,
        repick: repick,
        setEnabled: setEnabled,
        toggle: function () { setEnabled(!state.enabled); },
        get enabled() { return state.enabled; },
        get proxy() { return state.proxy; },
        get exitIp() { return state.exitIp; },
        get country() { return state.country; },
        get city() { return state.city; }
    };

    function start() {
        if (!patchFetch()) {
            console.warn("[proxy] BS.fetchJson bulunamadi, sorgular proxy uzerinden gonderilmeyecek.");
            return;
        }

        wireSwitch();

        var off = false;
        try { off = localStorage.getItem(OFF_KEY) === "1"; } catch (e) { /* yoksay */ }
        state.enabled = !off;
        syncSwitch();

        if (!state.enabled) {
            paintOff();
            return;
        }

        ensureProxy().catch(function (err) {
            paint("PROXY YOK", "error");
            console.warn("[proxy] proxy secilemedi:", err);
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start);
    } else {
        start();
    }
})();
