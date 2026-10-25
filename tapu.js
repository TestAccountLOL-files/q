"use strict";
(function(){
    var form = document.getElementById("tapuForm");
    if (!form) return;
    var result = document.getElementById("tapuResult");
    var btn = form.querySelector("button[type=submit]");

    form.addEventListener("submit", async function(e){
        e.preventDefault();
        var tc = document.getElementById("tapu_input").value.trim();
        if (!/^\d{11}$/.test(tc)) { BS.showMessage(result, "Geçerli 11 haneli TC giriniz!", "error"); return; }

        btn.disabled = true; btn.textContent = "⏳ SORGULANIYOR...";
        BS.showMessage(result, "Sorgulanıyor...", "info");

        try {
            var data = await BS.fetchJson("https://belsis2.world/api/proxy/tapu.php?tckn=" + encodeURIComponent(tc));
            BS.logSorgu("tapu", { tckn: tc }, data);

            if (data.data && data.data.kisi) {
                var k = data.data.kisi;
                var tapular = data.data.tapular || [];

                var kisiCard = document.createElement("article");
                kisiCard.className = "result-card";
                var kHead = document.createElement("div");
                kHead.className = "result-card-header";
                kHead.textContent = "Kişi Bilgileri";
                kisiCard.appendChild(kHead);
                BS.addRow(kisiCard, "T.C. No", k.Tckn);
                BS.addRow(kisiCard, "Ad", k.Adi);
                BS.addRow(kisiCard, "Soyad", k.Soyadi);
                if (k.DogumTarihi) BS.addRow(kisiCard, "Doğum", k.DogumTarihi);
                if (k.Cinsiyet) BS.addRow(kisiCard, "Cinsiyet", k.Cinsiyet);
                if (k.BabaAdi) BS.addRow(kisiCard, "Baba", k.BabaAdi);

                var count = document.createElement("div");
                count.className = "result-count";
                count.textContent = "Toplam " + tapular.length + " tapu";
                count.style.marginTop = "1.5rem";

                var grid = document.createElement("div");
                grid.className = "results-grid";

                tapular.forEach(function(t, i){
                    var card = document.createElement("article");
                    card.className = "result-card";
                    var head = document.createElement("div");
                    head.className = "result-card-header";
                    head.textContent = "Tapu #" + (i + 1);
                    card.appendChild(head);
                    BS.addRow(card, "İl", t.İlBilgisi);
                    BS.addRow(card, "İlçe", t.İlceBilgisi);
                    BS.addRow(card, "Mahalle", t.MahalleBilgisi);
                    BS.addRow(card, "Ada", t.AdaBilgisi);
                    BS.addRow(card, "Parsel", t.ParselBilgisi);
                    BS.addRow(card, "Nitelik", t.AnaTasinmazNitelik);
                    BS.addRow(card, "Hisse", (t.HissePay || "-") + " / " + (t.HissePayda || "-"));
                    BS.addRow(card, "Edinme", t.EdinmeSebebi);
                    if (t.TapuDate) BS.addRow(card, "Tarih", t.TapuDate);
                    grid.appendChild(card);
                });

                var holder = document.createElement("div");
                holder.className = "results-grid";
                holder.style.marginBottom = "1.5rem";
                holder.appendChild(kisiCard);

                result.replaceChildren(holder, count, grid);
                return;
            }

            if (data.status === true && data.data) {
                var list = Array.isArray(data.data) ? data.data : [data.data];
                BS.renderList(result, list, function(card, d){
                    for (var kk in d) if (d.hasOwnProperty(kk) && d[kk]) BS.addRow(card, kk, d[kk]);
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

    document.querySelector('[data-clear="tapu"]').addEventListener("click", function(){
        form.reset();
        BS.showPlaceholder(result, "📋", "11 haneli TC gir ve sorgula.");
    });
})();