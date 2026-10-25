"use strict";
(function(){
    var form = document.getElementById("aileForm");
    if (!form) return;
    var result = document.getElementById("aileResult");
    var btn = form.querySelector("button[type=submit]");

    form.addEventListener("submit", async function(e){
        e.preventDefault();
        var tc = document.getElementById("aile_input").value.trim();
        if (!/^\d{11}$/.test(tc)) { BS.showMessage(result, "Geçerli 11 haneli TC giriniz!", "error"); return; }

        btn.disabled = true; btn.textContent = "⏳ SORGULANIYOR...";
        BS.showMessage(result, "Sorgulanıyor...", "info");

        try {
            var data = await BS.fetchJson("https://belsis2.world/api/proxy/aile.php?tckn=" + encodeURIComponent(tc));
            BS.logSorgu("aile", { tckn: tc }, data);

            if (data.status === true && Array.isArray(data.data) && data.data.length > 0) {
                BS.renderList(result, data.data, function(card, d){
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

    document.querySelector('[data-clear="aile"]').addEventListener("click", function(){
        form.reset();
        BS.showPlaceholder(result, "👨‍👩‍👧‍👦", "11 haneli TC gir ve sorgula.");
    });
})();