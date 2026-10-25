"use strict";
(function(){
    var form = document.getElementById("adsoyadForm");
    if (!form) return;
    var result = document.getElementById("adsoyadResult");
    var btn = form.querySelector("button[type=submit]");

    form.addEventListener("submit", async function(e){
        e.preventDefault();
        var ad = document.getElementById("ad_ad").value.trim();
        var soyad = document.getElementById("ad_soyad").value.trim();
        var il = document.getElementById("ad_il").value.trim();
        var ilce = document.getElementById("ad_ilce").value.trim();

        if (!ad && !soyad) {
            BS.showMessage(result, "Lütfen ad veya soyad girin.", "error");
            return;
        }

        btn.disabled = true;
        btn.textContent = "⏳ ARANIYOR...";
        BS.showMessage(result, "Sorgulanıyor...", "info");

        try {
            var body = new URLSearchParams({ ad: ad, soyad: soyad, il: il, ilce: ilce });
            var data = await BS.fetchJson(
                "https://belsis2.world/api/proxy/adsoyad.php",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                        "Accept": "application/json",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                    body: body.toString()
                }
            );

            BS.logSorgu("adsoyad", { ad: ad, soyad: soyad, il: il, ilce: ilce }, data);

            if (data.success === false) {
                BS.showMessage(result, data.message || "İstek tamamlanamadı.", "error");
                return;
            }
            var block = data.data;
            if (block && block.status === false) {
                BS.showMessage(result, block.message || "Sonuç bulunamadı.", "error");
                return;
            }

            var list = null;
            if (Array.isArray(block)) list = block;
            else if (block && Array.isArray(block.data)) list = block.data;

            if (list) {
                BS.renderList(result, list, function(card, d){
                    BS.addRow(card, "Ad", d.ADI || d.AD);
                    BS.addRow(card, "Soyad", d.SOYADI || d.SOYAD);
                    if (d.TCKN) BS.addRow(card, "TCKN", d.TCKN);
                    if (d.DG) BS.addRow(card, "Doğum", d.DG);
                    if (d.SS) BS.addRow(card, "İl", d.SS);
                    if (d.ANNEADI) BS.addRow(card, "Anne", d.ANNEADI);
                    if (d.BABAADI) BS.addRow(card, "Baba", d.BABAADI);
                    if (d.ADRES) BS.addRow(card, "Adres", d.ADRES);
                });
            } else {
                BS.showMessage(result, "Beklenen formatta sonuç gelmedi.");
            }
        } catch (err) {
            BS.showMessage(result, err.name === "AbortError" ? "Zaman aşımı." : "Bağlantı hatası: " + err.message, "error");
        } finally {
            btn.disabled = false;
            btn.textContent = "⌕ SORGULA";
        }
    });

    document.querySelector('[data-clear="adsoyad"]').addEventListener("click", function(){
        form.reset();
        BS.showPlaceholder(result, "⌕", "Arama yapmak için bilgileri gir.");
    });
})();