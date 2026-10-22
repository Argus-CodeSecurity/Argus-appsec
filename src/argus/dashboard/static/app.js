// Argus Dashboard — theme persistence + client-side findings filter. No deps.
(function () {
  // --- theme toggle -------------------------------------------------------
  var root = document.documentElement;
  var saved = localStorage.getItem("argus-theme");
  if (saved) root.setAttribute("data-theme", saved);
  var toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var dark = root.getAttribute("data-theme") === "dark"
        || (!root.getAttribute("data-theme")
            && matchMedia("(prefers-color-scheme: dark)").matches);
      var next = dark ? "light" : "dark";
      root.setAttribute("data-theme", next);
      localStorage.setItem("argus-theme", next);
    });
  }

  // --- clickable table rows (no inline handlers: the CSP forbids them) ----
  function followRow(e) {
    var row = e.target.closest("tr[data-href]");
    if (!row) return;
    var href = row.getAttribute("data-href") || "";
    // Only same-origin absolute paths.
    if (href.charAt(0) !== "/" || href.charAt(1) === "/") return;
    location.href = href;
  }
  document.addEventListener("click", followRow);
  document.addEventListener("keydown", function (e) {
    if (e.key === "Enter") followRow(e);
  });

  // --- findings filter ----------------------------------------------------
  var search = document.getElementById("search");
  var sevFilter = document.getElementById("sev-filter");
  if (!search && !sevFilter) return;
  var findings = Array.prototype.slice.call(document.querySelectorAll(".finding"));
  var noMatch = document.getElementById("no-match");
  var activeSev = "all";
  var term = "";

  function apply() {
    var shown = 0;
    findings.forEach(function (f) {
      var sevOk = activeSev === "all" || f.getAttribute("data-sev") === activeSev;
      var textOk = !term || (f.getAttribute("data-text") || "").indexOf(term) !== -1;
      var visible = sevOk && textOk;
      f.hidden = !visible;
      if (visible) shown++;
    });
    if (noMatch) noMatch.hidden = shown !== 0;
  }

  if (search) {
    search.addEventListener("input", function () {
      term = search.value.trim().toLowerCase();
      apply();
    });
  }
  if (sevFilter) {
    sevFilter.addEventListener("click", function (e) {
      var btn = e.target.closest(".chip");
      if (!btn) return;
      activeSev = btn.getAttribute("data-sev");
      sevFilter.querySelectorAll(".chip").forEach(function (c) {
        c.classList.toggle("active", c === btn);
      });
      apply();
    });
  }
})();
