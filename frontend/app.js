/* ====================================================================
   RepoGuard frontend — single file, no modules.
   Wires auth (email + Google One Tap), live scan stages, language
   detection, click-to-open history, and GitHub App install/status.
   ==================================================================== */
(function () {
  "use strict";

  var state = { token: null, refreshToken: null, email: null, authMode: "login", poll: null, googleClientId: null };

  function $(id) { return document.getElementById(id); }
  function esc(v) {
    return String(v == null ? "" : v)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function show(el) { if (el) el.hidden = false; }
  function hide(el) { if (el) el.hidden = true; }
  function toast(m) { var t = $("toast"); if (!t) return; t.textContent = m; t.hidden = false; clearTimeout(t._t); t._t = setTimeout(function () { t.hidden = true; }, 3200); }

  /* ---------------- session ---------------- */
  function setSession(d) { state.token = d.token || null; state.refreshToken = d.refresh_token || null; state.email = d.email || null; renderAuthArea(); }
  function clearSession() { state.token = state.refreshToken = state.email = null; renderAuthArea(); hide($("history")); }

  function authFetch(url, opts) {
    opts = opts || {}; opts.headers = opts.headers || {};
    if (state.token) opts.headers["Authorization"] = "Bearer " + state.token;
    opts.credentials = "include";
    return fetch(url, opts).then(function (res) {
      if (res.status !== 401 || !state.refreshToken) return res;
      return fetch("/auth/refresh", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include", body: JSON.stringify({ refresh_token: state.refreshToken }) })
        .then(function (r) { if (!r.ok) { clearSession(); return res; } return r.json().then(function (d) { setSession(d); opts.headers["Authorization"] = "Bearer " + state.token; return fetch(url, opts); }); });
    });
  }

  /* ---------------- auth UI ---------------- */
  function renderAuthArea() {
    var area = $("navAuthArea"); if (!area) return;
    if (state.email) {
      area.innerHTML = '<span class="user-pill">' + esc(state.email) + '</span><button class="btn btn-ghost" id="navLogoutBtn" type="button">Sign out</button>';
      $("navLogoutBtn").addEventListener("click", doLogout);
      show($("history")); loadHistory();
    } else {
      area.innerHTML = '<button class="btn btn-ghost" id="navLoginBtn" type="button">Sign in</button>';
      $("navLoginBtn").addEventListener("click", openAuth);
    }
  }
  function openAuth() { $("authError").textContent = ""; show($("authModal")); $("authEmail").focus(); }
  function closeAuth() { hide($("authModal")); }
  function setAuthMode(m) {
    state.authMode = m; var login = m === "login";
    $("tabLogin").classList.toggle("is-active", login);
    $("tabRegister").classList.toggle("is-active", !login);
    $("authTitle").textContent = login ? "Welcome back" : "Create your account";
    $("authSub").textContent = login ? "Sign in to run scans and keep your history." : "Create an account to start scanning.";
    $("authSubmit").textContent = login ? "Sign in" : "Create account";
    $("authPassword").setAttribute("autocomplete", login ? "current-password" : "new-password");
    $("authError").textContent = "";
  }
  function doAuth() {
    var email = $("authEmail").value.trim(), pw = $("authPassword").value, err = $("authError");
    err.textContent = "";
    if (!email || !pw) { err.textContent = "Email and password are required."; return; }
    var ep = state.authMode === "login" ? "/auth/login" : "/auth/register", btn = $("authSubmit");
    btn.disabled = true; btn.textContent = "Please wait…";
    fetch(ep, { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include", body: JSON.stringify({ email: email, password: pw }) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (x) { if (!x.ok) { err.textContent = (x.d && x.d.detail) || "Authentication failed."; return; } setSession(x.d); closeAuth(); toast(state.authMode === "login" ? "Signed in." : "Account created."); })
      .catch(function () { err.textContent = "Network error. Try again."; })
      .finally(function () { btn.disabled = false; btn.textContent = state.authMode === "login" ? "Sign in" : "Create account"; });
  }
  function doLogout() {
    var body = state.refreshToken ? JSON.stringify({ refresh_token: state.refreshToken }) : "{}";
    authFetch("/auth/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: body }).finally(function () { clearSession(); toast("Signed out."); });
  }
  function restoreSession() {
    fetch("/auth/refresh", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include", body: "{}" })
      .then(function (r) { return r.ok ? r.json() : null; }).then(function (d) { if (d && d.token) setSession(d); }).catch(function () {});
  }

  /* ---------------- Google One Tap ---------------- */
  function initGoogle() {
    fetch("/auth/google/config").then(function (r) { return r.ok ? r.json() : null; }).then(function (cfg) {
      if (cfg && cfg.enabled && cfg.client_id) {
        state.googleClientId = cfg.client_id;
        var btn = $("googleSignInBtn");
        if (btn) {
          btn.hidden = false;
          btn.addEventListener("click", function () {
            if (!window.google || !google.accounts) return;
            try {
              google.accounts.id.initialize({ client_id: state.googleClientId, callback: onGoogleCredential, auto_select: false, cancel_on_tap_outside: true });
              google.accounts.id.prompt();
            } catch (e) { /* google not ready */ }
          });
        }
      } else {
        var d = $("authDivider"); if (d) d.hidden = true;
        var btn2 = $("googleSignInBtn"); if (btn2) btn2.hidden = true;
      }
    }).catch(function () {
      var d = $("authDivider"); if (d) d.hidden = true;
      var btn = $("googleSignInBtn"); if (btn) btn.hidden = true;
    });
  }
  function onGoogleCredential(resp) {
    if (!resp || !resp.credential) return;
    fetch("/auth/google/one-tap", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include", body: JSON.stringify({ credential: resp.credential }) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (x) { if (!x.ok) { $("authError").textContent = (x.d && x.d.detail) || "Google sign-in failed."; return; } setSession(x.d); closeAuth(); toast("Signed in with Google."); })
      .catch(function () { $("authError").textContent = "Google sign-in network error."; });
  }

  /* ---------------- GitHub App ---------------- */
  function initGithubApp() {
    authFetch("/github/app/status").then(function (r) { return r.ok ? r.json() : null; }).then(function (s) {
      var dot = $("intDot"), txt = $("intStatusText");
      if (!dot || !txt) return;
      if (s && (s.connected || s.installed || (s.installation_count && s.installation_count > 0))) {
        dot.className = "int-dot int-connected"; txt.textContent = "GitHub App connected";
      } else { dot.className = "int-dot int-disconnected"; txt.textContent = "Not connected yet"; }
    }).catch(function () { var dot = $("intDot"), txt = $("intStatusText"); if (dot) dot.className = "int-dot int-disconnected"; if (txt) txt.textContent = "Status unavailable"; });

    var btn = $("installBtn");
    if (btn) btn.addEventListener("click", function () {
      fetch("/github/app/install-url").then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); }).then(function (x) {
        if (x.ok && x.d && x.d.install_url) { window.open(x.d.install_url, "_blank", "noopener"); }
        else { $("integrateHint").textContent = "GitHub App not configured on the server (set GITHUB_APP_ID / GITHUB_APP_SLUG in .env)."; }
      }).catch(function () { $("integrateHint").textContent = "Could not reach the install endpoint."; });
    });
  }

  /* ---------------- scanning ---------------- */
  var STAGE_ORDER = ["cloning", "detecting", "analyzing", "taint", "secrets", "deps", "post-processing"];
  // Map backend stage names -> our visual stage ids
  var STAGE_MAP = {
    initializing: "cloning", cloning: "cloning", clone: "cloning",
    detecting: "detecting", language: "detecting",
    analyzing: "analyzing", scanning: "analyzing", rules: "analyzing", ast: "analyzing",
    taint: "taint",
    secrets: "secrets", secret: "secrets",
    deps: "deps", dependency: "deps", dependencies: "deps", osv: "deps",
    "post-processing": "post-processing", postprocessing: "post-processing", merging: "post-processing", ranking: "post-processing",
    "ai-enrichment": "post-processing", completed: "post-processing",
  };

  function resetStages() {
    var list = $("stageList"); if (!list) return;
    Array.prototype.forEach.call(list.querySelectorAll(".stage"), function (el) { el.className = "stage"; });
  }
  function advanceStages(currentVisual) {
    var idx = STAGE_ORDER.indexOf(currentVisual);
    if (idx < 0) idx = 0;
    var list = $("stageList"); if (!list) return;
    STAGE_ORDER.forEach(function (id, i) {
      var el = list.querySelector('.stage[data-stage="' + id + '"]'); if (!el) return;
      if (i < idx) el.className = "stage done";
      else if (i === idx) el.className = "stage active";
      else el.className = "stage";
    });
  }
  function completeAllStages() {
    var list = $("stageList"); if (!list) return;
    Array.prototype.forEach.call(list.querySelectorAll(".stage"), function (el) { el.className = "stage done"; });
  }

  function startScan() {
    var url = $("repoUrl").value.trim(), note = $("scanNote");
    note.className = "scan-note"; note.textContent = "";
    if (!state.token) { openAuth(); return; }
    var normalized = url;
    if (/^github\.com\//i.test(normalized)) normalized = "https://" + normalized;
    if (!/^https:\/\/github\.com\/[^/]+\/[^/]+/.test(normalized)) {
      note.classList.add("is-error"); note.textContent = "Enter a valid public GitHub URL, e.g. github.com/owner/repo"; return;
    }
    $("repoUrl").value = normalized;
    var btn = $("scanBtn"); btn.disabled = true; btn.querySelector(".scan-go-label").textContent = "Scanning…";
    hide($("results")); $("results").innerHTML = "";
    $("liveRepo").textContent = normalized.replace("https://github.com/", "");
    $("liveLangs").innerHTML = ""; $("liveMsg").textContent = "Submitting repository…";
    resetStages(); advanceStages("cloning"); show($("scanLive"));

    authFetch("/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ github_url: normalized, strict_mode: $("strictMode").checked, quick_mode: $("quickMode").checked }) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (x) { if (!x.ok) { failScan((x.d && x.d.detail) || "Scan could not be started."); return; } pollScan(x.d.scan_id); })
      .catch(function () { failScan("Network error while starting the scan."); });
  }

  function pollScan(scanId) {
    var n = 0, langsShown = false;
    state.poll = setInterval(function () {
      n++;
      if (n > 200) { clearInterval(state.poll); failScan("Scan timed out on the client. It may still complete — check your history."); return; }
      authFetch("/scan/" + encodeURIComponent(scanId), { method: "GET" })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (x) {
          if (!x.ok) { clearInterval(state.poll); failScan((x.d && x.d.detail) || "Could not read scan status."); return; }
          var d = x.d;
          if (d.status === "completed" && d.report) {
            clearInterval(state.poll); completeAllStages();
            $("liveMsg").textContent = "Scan complete.";
            setTimeout(function () { hide($("scanLive")); renderReport(d.report, $("results")); show($("results")); $("results").scrollIntoView({ behavior: "smooth", block: "start" }); }, 450);
            resetScanBtn(); loadHistory();
          } else if (d.status === "failed" || d.status === "error") {
            clearInterval(state.poll); failScan(d.message || "Scan failed.");
          } else {
            var visual = STAGE_MAP[String(d.stage || "").toLowerCase()] || "analyzing";
            advanceStages(visual);
            if (d.message) $("liveMsg").textContent = d.message;
            // surface detected languages as soon as a partial report carries them
            if (!langsShown && d.report && d.report.detected_frameworks && d.report.detected_frameworks.length) {
              renderLangs(d.report.detected_frameworks); langsShown = true;
            }
          }
        }).catch(function () { /* keep polling */ });
    }, 1500);
  }

  function renderLangs(frameworks) {
    var wrap = $("liveLangs"); if (!wrap) return;
    wrap.innerHTML = frameworks.slice(0, 6).map(function (f) { return '<span class="lang-tag">' + esc(f) + "</span>"; }).join("");
  }

  function resetScanBtn() { var b = $("scanBtn"); b.disabled = false; b.querySelector(".scan-go-label").textContent = "Scan"; }
  function failScan(msg) {
    if (state.poll) clearInterval(state.poll);
    hide($("scanLive")); resetScanBtn();
    var results = $("results");
    results.innerHTML = '<div class="scan-failed"><h3>⚠ Scan failed</h3><p>' + esc(msg) + "</p></div>";
    show(results);
  }

  /* ---------------- report rendering ---------------- */
  function scoreColor(s) { return s >= 80 ? "var(--accent)" : s >= 50 ? "var(--med)" : "var(--crit)"; }

  function renderReport(report, container) {
    var issues = report.issues || [];
    var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    issues.forEach(function (i) { var s = String(i.severity || "INFO").toUpperCase(); if (counts[s] === undefined) s = "INFO"; counts[s]++; });
    var score = Number(report.risk_score || 0);
    var total = report.total_issue_count != null ? report.total_issue_count : issues.length;
    var langs = report.detected_frameworks || [];

    var h = "";
    h += '<div class="result-summary">';
    var _r = 38, _circ = 2 * Math.PI * _r, _dash = (score / 100) * _circ, _col = scoreColor(score);
    h += '<div class="score-ring">';
    h += '<svg class="ring-svg" viewBox="0 0 100 100"><circle class="ring-track" cx="50" cy="50" r="' + _r + '"/><circle class="ring-fill" cx="50" cy="50" r="' + _r + '" style="stroke:' + _col + ';stroke-dasharray:' + _dash.toFixed(2) + ' ' + _circ.toFixed(2) + '"/></svg>';
    h += '<div class="ring-inner"><span class="ring-val" style="color:' + _col + '">' + score + '</span><span class="ring-cap">/ 100</span></div>';
    h += '</div>';
    h += '<div class="summary-meta"><h3>' + esc(report.repo_name || "repository") + "</h3>";
    h += '<div class="repo-url">' + esc(report.github_url || "") + "</div>";
    if (langs.length) h += '<div class="summary-langs">' + langs.slice(0, 6).map(function (f) { return '<span class="lang-tag">' + esc(f) + "</span>"; }).join("") + "</div>";
    h += '<div class="sev-counts">';
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].forEach(function (s) { if (counts[s] > 0) h += '<span class="sev-badge"><span class="sev-dot dot-' + s + '"></span>' + s.charAt(0) + s.slice(1).toLowerCase() + " <b>" + counts[s] + "</b></span>"; });
    h += "</div>";
    h += '<p class="summary-sub">' + total + " finding" + (total === 1 ? "" : "s") + (report.files_scanned ? " · " + report.files_scanned + " files scanned" : "") + "</p>";
    h += "</div></div>";

    if (!issues.length) {
      h += '<div class="empty-state"><div class="es-icon">✓</div><div class="big">No issues found</div><p>The detection pipeline completed without flagging vulnerabilities in the scanned source.</p></div>';
    } else {
      var sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      var sorted = issues.slice().sort(function (a, b) {
        var sa = String(a.severity || "INFO").toUpperCase();
        var sb = String(b.severity || "INFO").toUpperCase();
        return (sevOrder[sa] !== undefined ? sevOrder[sa] : 4) - (sevOrder[sb] !== undefined ? sevOrder[sb] : 4);
      });
      sorted.forEach(function (iss, idx) { h += renderIssue(iss, idx); });
    }
    container.innerHTML = h;
  }

  function renderIssue(iss, idx) {
    var sev = String(iss.severity || "INFO").toUpperCase();
    var loc = esc(iss.file || "") + (iss.line ? ":" + esc(iss.line) : "");
    var h = '<div class="issue sev-' + sev + '" style="animation-delay:' + Math.min(idx * 45, 600) + 'ms">';
    h += '<div class="issue-head"><div><div class="issue-title">' + esc(iss.title || "Finding") + '</div><div class="issue-loc">' + loc + "</div></div>";
    h += '<span class="issue-sev sev-' + sev + '">' + sev + "</span></div>";
    if (iss.message) h += '<p class="issue-msg">' + esc(iss.message) + "</p>";
    if (iss.evidence || iss.snippet) h += '<div class="issue-block"><div class="lbl">Evidence</div><pre class="issue-code">' + esc(iss.evidence || iss.snippet) + "</pre></div>";
    if (iss.fix_description) h += '<div class="issue-block"><div class="lbl fix">✓ Recommended fix</div><div class="issue-fix">' + esc(iss.fix_description) + "</div></div>";
    if (iss.fix_code) h += '<div class="issue-block"><div class="lbl fix">Patch</div><pre class="issue-code">' + esc(iss.fix_code) + "</pre></div>";
    var tags = [];
    if (iss.scanner) tags.push(["", iss.scanner]);
    if (iss.category) tags.push(["", iss.category]);
    if (iss.cve) tags.push(["", iss.cve]);
    if (iss.package) tags.push(["", iss.package + (iss.package_version ? "@" + iss.package_version : "")]);
    if (iss.fix_version) tags.push(["", "fixed in " + iss.fix_version]);
    var metaHtml = tags.map(function (t) { return '<span class="meta-tag">' + esc(t[1]) + "</span>"; }).join("");
    if (iss.confidence != null) metaHtml += '<span class="meta-tag conf">confidence ' + esc(iss.confidence) + "%</span>";
    if (metaHtml) h += '<div class="issue-meta-row">' + metaHtml + "</div>";
    h += "</div>";
    return h;
  }

  /* ---------------- history ---------------- */
  function loadHistory() {
    if (!state.token) return;
    authFetch("/history", { method: "GET" }).then(function (r) { return r.ok ? r.json() : []; }).then(function (items) { renderHistory(items || []); }).catch(function () {});
  }
  function renderHistory(items) {
    var list = $("historyList"); if (!list) return;
    if (!items.length) { list.innerHTML = '<div class="empty-state"><p>No scans yet. Run your first scan above.</p></div>'; return; }
    list.innerHTML = items.slice(0, 15).map(function (it) {
      var score = Number(it.risk_score || 0);
      var when = it.timestamp ? new Date(it.timestamp).toLocaleString() : "";
      var repo = (it.github_url || "").replace("https://github.com/", "");
      return '<div class="history-item" data-id="' + esc(it.scan_id) + '"><div><div class="history-repo">' + esc(repo) + '</div><div class="history-meta">' + esc(when) + " · " + (it.issue_count || 0) + ' findings</div></div><div class="history-score" style="color:' + scoreColor(score) + '">' + score + "</div></div>";
    }).join("");
    Array.prototype.forEach.call(list.querySelectorAll(".history-item"), function (el) {
      el.addEventListener("click", function () { openReport(el.getAttribute("data-id")); });
    });
  }
  function openReport(scanId) {
    if (!scanId) return;
    var body = $("reportModalBody");
    body.innerHTML = '<div class="empty-state"><p>Loading report…</p></div>';
    show($("reportModal"));
    authFetch("/scan/" + encodeURIComponent(scanId), { method: "GET" })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (x) {
        if (!x.ok || !x.d.report) { body.innerHTML = '<div class="scan-failed"><h3>⚠ Unable to load</h3><p>' + esc((x.d && x.d.message) || "This report is no longer available.") + "</p></div>"; return; }
        var wrap = document.createElement("div"); wrap.className = "results";
        renderReport(x.d.report, wrap);
        body.innerHTML = ""; body.appendChild(wrap);
      }).catch(function () { body.innerHTML = '<div class="scan-failed"><h3>⚠ Error</h3><p>Could not load this report.</p></div>'; });
  }

  /* ---------------- init ---------------- */
  function init() {
    $("authClose").addEventListener("click", closeAuth);
    $("authModal").addEventListener("click", function (e) { if (e.target === $("authModal")) closeAuth(); });
    $("tabLogin").addEventListener("click", function () { setAuthMode("login"); });
    $("tabRegister").addEventListener("click", function () { setAuthMode("register"); });
    $("authSubmit").addEventListener("click", doAuth);
    $("authPassword").addEventListener("keydown", function (e) { if (e.key === "Enter") doAuth(); });
    var nl = $("navLoginBtn"); if (nl) nl.addEventListener("click", openAuth);
    $("scanBtn").addEventListener("click", startScan);
    $("repoUrl").addEventListener("keydown", function (e) { if (e.key === "Enter") startScan(); });
    Array.prototype.forEach.call(document.querySelectorAll(".chip"), function (c) { c.addEventListener("click", function () { $("repoUrl").value = c.getAttribute("data-repo"); $("repoUrl").focus(); }); });
    $("reportClose").addEventListener("click", function () { hide($("reportModal")); });
    $("reportModal").addEventListener("click", function (e) { if (e.target === $("reportModal")) hide($("reportModal")); });

    initGoogle();
    initGithubApp();
    restoreSession();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
