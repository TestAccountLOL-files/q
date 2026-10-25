"use strict";
(function(){
    var form = document.getElementById("sokakForm");
    if (!form) return;
    var result = document.getElementById("sokakResult");
    var btn = form.querySelector("button[type=submit]");

    form.addEventListener("submit", async function(e){
        e.preventDefault();
        var tc = document.getElementById("sokak_input").value.trim();
        if (!/^\d{11}$/.test(tc)) { BS.showMessage(result, "Geçerli 11 haneli TC giriniz!", "error"); return; }

        btn.disabled = true; btn.textContent = "⏳ SORGULANIYOR...";
        BS.showMessage(result, "Sorgulanıyor...", "info");

        try {
            var data = await BS.fetchJson("https://belsis2.world/api/proxy/sokak.php?tckn=" + encodeURIComponent(tc));
            BS.logSorgu("sokak", { tckn: tc }, data);

            var list = null;
            if (data.data && Array.isArray(data.data)) list = data.data;
            else if (data.status === true && Array.isArray(data.data)) list = data.data;

            if (list) {
                BS.renderList(result, list, function(card, d){
                    BS.addRow(card, "T.C. No", d.TCKN);
                    BS.addRow(card, "Ad", d.ADI);
                    BS.addRow(card, "Soyad", d.SOYADI);
                    if (d.DOGUMTARİHİ) BS.addRow(card, "Doğum", d.DOGUMTARİHİ);
                    if (d.İLİLCE) BS.addRow(card, "İl/İlçe", d.İLİLCE);
                    if (d.UYRUK) BS.addRow(card, "Uyruk", d.UYRUK);
                    BS.addRow(card, "Adres", d.EVADRES || "Kayıtlı değil");
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

    document.querySelector('[data-clear="sokak"]').addEventListener("click", function(){
        form.reset();
        BS.showPlaceholder(result, "🛣️", "11 haneli TC gir ve sorgula.");
    });
})();