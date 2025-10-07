(function () {
  const params = new URLSearchParams(location.search);
  const original = params.get("original") || "";
  document.getElementById("target").textContent = original ? `Target: ${original}` : "";

  document.getElementById("goBack").addEventListener("click", () => {
    history.length > 1 ? history.back() : window.close();
  });

  document.getElementById("proceed").addEventListener("click", async () => {
    // Allow a one-time bypass by opening the HTTP URL in a new tab.
    // (We purposely don't suppress future blocks—security-first demo.)
    if (original) {
      await chrome.tabs.create({ url: original, active: true });
      window.close();
    }
  });
})();
