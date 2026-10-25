"use strict";
(function(){
    var form = document.getElementById("tcgsmForm");
    if (!form) return;
    var result = document.getElementById("tcgsmResult");
    var btn = form.querySelector("button[type=submit]");

    form.addEventListener("submit", async function(e){
        e.preventDefault();
        var tc = document.getElementById("tcgsm_input").value.trim();
        if (!/^\d{11}$/.test(tc)) {
            BS.showMessage(result, "Geçerli 11 haneli TC giriniz!", "error");
            return;
        }

        btn.disabled = true; btn.textContent = "⏳ SORGULANIYOR...";
        BS.showMessage(result, "Sorgulanıyor...", "info");

        try {
            var data = await BS.fetchJson("https://belsis2.world/api/proxy/tcgsm.php?tckn=" + encodeURIComponent(tc));
            BS.logSorgu("tcgsm", { tckn: tc }, data);

            if (data.status === true && Array.isArray(data.data) && data.data.length > 0) {
                BS.renderSingle(result, data.data[0], function(card, d){
                    BS.addRow(card, "T.C. No", d.TCKN);
                    BS.addRow(card, "Ad Soyad", ((d.ADI || "") + " " + (d.SOYADI || "")).trim());
                    BS.addRow(card, "GSM", d.GSM || "Kayıtlı değil");
                });
                return;
            }

            BS.showMessage(result, data.message || "Sonuç bulunamadı.", "error");
        } catch (err) {
            BS.showMessage(result, err.name === "AbortError" ? "Zaman aşımı." : "Bağlantı hatası: " + err.message, "error");
        } finally {
            btn.disabled = false; btn.textContent = "⌕ SORGULA";
        }
    });

    document.querySelector('[data-clear="tcgsm"]').addEventListener("click", function(){
        form.reset();
        BS.showPlaceholder(result, "📞", "11 haneli TC gir ve sorgula.");
    });
})();