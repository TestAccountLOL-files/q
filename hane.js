"use strict";
(function(){
    var form = document.getElementById("haneForm");
    if (!form) return;
    var result = document.getElementById("haneResult");
    var btn = form.querySelector("button[type=submit]");

    form.addEventListener("submit", async function(e){
        e.preventDefault();
        var tc = document.getElementById("hane_input").value.trim();
        if (!/^\d{11}$/.test(tc)) { BS.showMessage(result, "Geçerli 11 haneli TC giriniz!", "error"); return; }

        btn.disabled = true; btn.textContent = "⏳ SORGULANIYOR...";
        BS.showMessage(result, "Sorgulanıyor...", "info");

        try {
            var data = await BS.fetchJson("https://belsis2.world/api/proxy/hane.php?tckn=" + encodeURIComponent(tc));
            BS.logSorgu("hane", { tckn: tc }, data);

            var list = null;
            if (data.status === true && Array.isArray(data.data)) list = data.data;
            else if (Array.isArray(data.data)) list = data.data;

            if (list) {
                BS.renderList(result, list, function(card, d){
                    BS.addRow(card, "Yakınlık", d.YAKINLIK);
                    BS.addRow(card, "T.C. No", d.TCKN);
                    BS.addRow(card, "Ad Soyad", ((d.ADI || "") + " " + (d.SOYADI || "")).trim());
                    BS.addRow(card, "Doğum", d.DG);
                    BS.addRow(card, "İl", d.IL);
                    if (d.UYRUK) BS.addRow(card, "Uyruk", d.UYRUK);
                    BS.addRow(card, "GSM", d.GSM || "Kayıtlı değil");
                    BS.addRow(card, "Adres", d.ADRES || "Kayıtlı değil");
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

    document.querySelector('[data-clear="hane"]').addEventListener("click", function(){
        form.reset();
        BS.showPlaceholder(result, "🏘️", "11 haneli TC gir ve sorgula.");
    });
})();