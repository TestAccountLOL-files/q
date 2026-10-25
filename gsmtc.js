"use strict";
(function(){
    var form = document.getElementById("gsmtcForm");
    if (!form) return;
    var result = document.getElementById("gsmtcResult");
    var btn = form.querySelector("button[type=submit]");

    // Sayfa açıldığında bakım mesajı
    BS.showMessage(result, "🛠️ Şu an bakımda...", "maintenance");

    form.addEventListener("submit", function(e){
        e.preventDefault();
        BS.showMessage(result, "🛠️ Şu an bakımda...", "maintenance");
    });

    document.querySelector('[data-clear="gsmtc"]').addEventListener("click", function(){
        form.reset();
        BS.showMessage(result, "🛠️ Şu an bakımda...", "maintenance");
    });
})();