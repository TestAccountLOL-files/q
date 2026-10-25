"use strict";
(function(){
    var form = document.getElementById("adresForm");
    if (!form) return;
    var result = document.getElementById("adresResult");
    var btn = form.querySelector("button[type=submit]");

    form.addEventListener("submit", async function(e){
        e.preventDefault();
        var tc = document.getElementById("adres_input").value.trim();
        if (!/^\d{11}$/.test(tc)) { BS.showMessage(result, "Geçerli 11 haneli TC giriniz!", "error"); return; }

        btn.disabled = true; btn.textContent = "⏳ SORGULANIYOR...";
        BS.showMessage(result, "Sorgulanıyor...", "info");

        try {
            var data = await BS.fetchJson("https://belsis2.world/api/proxy/adres.php?tckn=" + encodeURIComponent(tc));
            BS.logSorgu("adres", { tckn: tc }, data);

            var list = null;
            if (data.status === true && data.data) {
                list = Array.isArray(data.data) ? data.data : [data.data];
            }
            if (list && list.length > 0) {
                BS.renderList(result, list, function(card, d){
                    BS.addRow(card, "T.C. No", d.TCKN || d.TC);
                    BS.addRow(card, "Ad Soyad", ((d.ADI || d.AD || "") + " " + (d.SOYADI || d.SOYAD || "")).trim());
                    if (d.DG || d.DOGUMTARIHI) BS.addRow(card, "Doğum", d.DG || d.DOGUMTARIHI);
                    BS.addRow(card, "Adres", d.ADRES || d.EVADRES || "Kayıtlı değil");
                    if (d.ILILCE) BS.addRow(card, "İl/İlçe", d.ILILCE);
                    if (d.GSM) BS.addRow(card, "GSM", d.GSM);
                });
                return;
            }
            if (data.data && typeof data.data === "object" && !Array.isArray(data.data)) {
                BS.renderSingle(result, data.data, function(card, d){
                    for (var k in d) if (d.hasOwnProperty(k) && d[k]) BS.addRow(card, k, d[k]);
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

    document.querySelector('[data-clear="adres"]').addEventListener("click", function(){
        form.reset();
        BS.showPlaceholder(result, "📍", "11 haneli TC gir ve sorgula.");
    });
})();