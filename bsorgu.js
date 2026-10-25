"use strict";

window.BS = {
    showMessage: function(resultEl, message, type) {
        var box = document.createElement("div");
        box.className = "message " + (type || "");
        box.textContent = message;
        resultEl.replaceChildren(box);
    },

    showPlaceholder: function(resultEl, icon, text) {
        var w = document.createElement("div");
        w.className = "placeholder";
        var i = document.createElement("div");
        i.className = "placeholder-icon";
        i.textContent = icon || "⌕";
        var p = document.createElement("p");
        p.textContent = text || "Arama yapmak için bilgileri gir.";
        w.append(i, p);
        resultEl.replaceChildren(w);
    },

    addRow: function(card, label, value) {
        var row = document.createElement("div");
        row.className = "result-row";
        var l = document.createElement("div");
        l.className = "result-label";
        l.textContent = label;
        var v = document.createElement("div");
        v.className = "result-value";
        v.textContent = (value === undefined || value === null || value === "") ? "-" : String(value);
        row.append(l, v);
        card.appendChild(row);
    },

    renderList: function(resultEl, list, rowBuilder) {
        if (!Array.isArray(list) || list.length === 0) {
            this.showMessage(resultEl, "Sonuç bulunamadı.", "error");
            return;
        }
        var count = document.createElement("div");
        count.className = "result-count";
        count.textContent = "Toplam " + list.length + " sonuç";

        var grid = document.createElement("div");
        grid.className = "results-grid";

        list.forEach(function(item, index){
            var record = item && typeof item === "object" ? item : {};
            var card = document.createElement("article");
            card.className = "result-card";
            var head = document.createElement("div");
            head.className = "result-card-header";
            head.textContent = "Kayıt #" + (index + 1);
            card.appendChild(head);
            rowBuilder(card, record);
            grid.appendChild(card);
        });

        resultEl.replaceChildren(count, grid);
    },

    renderSingle: function(resultEl, record, rowBuilder) {
        var card = document.createElement("article");
        card.className = "result-card";
        var head = document.createElement("div");
        head.className = "result-card-header";
        head.textContent = "Sonuç";
        card.appendChild(head);
        rowBuilder(card, record || {});
        resultEl.replaceChildren(card);
    },

    fetchJson: async function(url, options, timeoutMs) {
        var controller = new AbortController();
        var timer = setTimeout(function(){ controller.abort(); }, timeoutMs || 25000);
        try {
            var response = await fetch(url, Object.assign({
                signal: controller.signal,
                headers: {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest"
                }
            }, options || {}));
            if (!response.ok) throw new Error("HTTP " + response.status);
            return await response.json();
        } finally {
            clearTimeout(timer);
        }
    },

    logSorgu: function(type, input, result) {
        if (window.BSAdmin && typeof window.BSAdmin.log === "function") {
            try { window.BSAdmin.log({ type: type, input: input, result: result }); }
            catch(e) { console.warn("log error", e); }
        }
    }
};