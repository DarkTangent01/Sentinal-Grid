// Applies the saved/preferred theme before first paint. Separate file so the strict CSP (script-src 'self') holds.
(function () {
  try {
    var t = localStorage.getItem("siem.theme");
    if (t !== "light" && t !== "dark") t = "light"; // Zomato theme: day by default
    document.documentElement.className = t;
  } catch (e) {}
})();
