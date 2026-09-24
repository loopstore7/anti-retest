document.addEventListener("click", function (ev) {
  var btn = ev.target.closest(".copiar");
  if (!btn || !btn.dataset.copia) return;
  navigator.clipboard.writeText(btn.dataset.copia).then(function () {
    btn.textContent = "✓";
    setTimeout(function () { btn.textContent = "⧉"; }, 1200);
  });
});
