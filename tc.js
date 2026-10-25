"use strict";
(function(){
    var form = document.getElementById("tcForm");
    if (!form) return;
    var result = document.getElementById("tcResult");
    var btn = form.querySelector("button[type=submit]");

    form.addEventListener("submit", async function(e){
        e.preventDefault();
        var tc = document.getElementById("tc_input").value.trim();
        if (!/^\d{11}$/.test(tc)) {
            BS.showMessage(result, "Geçerli 11 haneli TC giriniz!", "error");
            return;
        }

        btn.disabled = true; btn.textContent = "⏳ SORGULANIYOR...";
        BS.showMessage(result, "Sorgulanıyor...", "info");

        try {
            var data = await BS.fetchJson("https://belsis2.world/api/proxy/tc.php?tckn=" + encodeURIComponent(tc));
            BS.logSorgu("tc", { tckn: tc }, data);

            if (data.status === true && Array.isArray(data.data) && data.data.length > 0) {
                BS.renderSingle(result, data.data[0], function(card, d){
                    BS.addRow(card, "T.C. No", d.TCKN);
                    BS.addRow(card, "Ad Soyad", ((d.ADI || "") + " " + (d.SOYADI || "")).trim());
                    if (d.DG) BS.addRow(card, "Doğum", d.DG);
                    if (d.YAS) BS.addRow(card, "Yaş", d.YAS);
                    if (d.CINSIYET) BS.addRow(card, "Cinsiyet", d.CINSIYET);
                    if (d.MEDENIHAL) BS.addRow(card, "Medeni Hal", d.MEDENIHAL);
                    if (d.ANNEADI) BS.addRow(card, "Anne", d.ANNEADI + (d.ANNETC ? " (" + d.ANNETC + ")" : ""));
                    if (d.BABAADI) BS.addRow(card, "Baba", d.BABAADI + (d.BABATC ? " (" + d.BABATC + ")" : ""));
                    if (d.DOGUMYERI) BS.addRow(card, "Doğum Yeri", d.DOGUMYERI);
                    if (d.MEMLEKETIL) BS.addRow(card, "Memleket", d.MEMLEKETIL + " / " + (d.MEMLEKETILCE || ""));
                    if (d.ADRES) BS.addRow(card, "Adres", d.ADRES);
                    if (d.GSM) BS.addRow(card, "GSM", d.GSM);
                    if (d.ILILCE) BS.addRow(card, "İl/İlçe", d.ILILCE);
                    if (d.UYRUK) BS.addRow(card, "Uyruk", d.UYRUK);
                });
                return;
            }

            if (data.data && typeof data.data === "object" && !Array.isArray(data.data)) {
                BS.renderSingle(result, data.data, function(card, d){
                    for (var k in d) {
                        if (d.hasOwnProperty(k) && d[k]) BS.addRow(card, k, d[k]);
                    }
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

    document.querySelector('[data-clear="tc"]').addEventListener("click", function(){
        form.reset();
        BS.showPlaceholder(result, "🪪", "11 haneli TC gir ve sorgula.");
    });
})();