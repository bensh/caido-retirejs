export const init = async (sdk) => {
  const RETIRE_DB_URL =
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json";

  //
  // Helpers
  //

  function compareVersions(a, b) {
    if (!a || !b) return 0;
    const pa = String(a)
      .split(/[^0-9a-zA-Z]+/)
      .filter(Boolean);
    const pb = String(b)
      .split(/[^0-9a-zA-Z]+/)
      .filter(Boolean);
    const n = Math.max(pa.length, pb.length);
    for (let i = 0; i < n; i++) {
      const va = pa[i] || "0";
      const vb = pb[i] || "0";
      const na = /^\d+$/.test(va) ? parseInt(va, 10) : va;
      const nb = /^\d+$/.test(vb) ? parseInt(vb, 10) : vb;
      if (na > nb) return 1;
      if (na < nb) return -1;
    }
    return 0;
  }

  function getPrefs() {
    const stored = sdk.storage.get();
    const defaults = {
      autoExpandHighs: true,
      autoCreateFindings: false,
      showSummaries: true,
      limit: 100,
      inScopeOnly: true,
      query: "",
    };
    if (!stored || typeof stored !== "object") return defaults;
    return { ...defaults, ...stored };
  }

  async function savePrefs(next) {
    const existing = sdk.storage.get() || {};
    await sdk.storage.set({ ...existing, ...next });
  }

  async function loadDb(force = false) {
    const cached = sdk.storage.get();
    if (cached && cached.__db && !force) return cached.__db;

    const res = await fetch(RETIRE_DB_URL);
    if (!res.ok) throw new Error("Failed to fetch Retire.js DB");
    const db = await res.json();

    const prefs = getPrefs();
    await sdk.storage.set({ ...prefs, __db: db });
    return db;
  }

  function severityIcon(sev) {
    if (sev === "high") return "🔥";
    if (sev === "medium") return "⚠️";
    if (sev === "low") return "ℹ️";
    return "🧱";
  }

  function highestSeverity(findings) {
    let hasHigh = false,
      hasMed = false;
    for (const f of findings) {
      const sev = (f.severity || "").toLowerCase();
      if (sev === "high") hasHigh = true;
      else if (sev === "medium") hasMed = true;
    }
    return hasHigh ? "high" : hasMed ? "medium" : "low";
  }


  //
  // UI skeleton
  //


  const root = document.createElement("div");
  Object.assign(root.style, { height: "100%", width: "100%" });
  root.id = "plugin--frontend-vue";

  const panel = document.createElement("div");
  panel.id = "retirejs-panel"; 

  root.innerHTML = `
    <div class="toolbar">
      <div class="toolbar-row1">
        <input id="search" type="text" placeholder="Search URL or library..." />
        <label><input id="auto-expand" type="checkbox" /> Auto-expand highs</label>
        <label><input id="auto-findings" type="checkbox" /> Auto-create Findings</label>
        <label><input id="show-summaries" type="checkbox" checked /> Show summaries &amp; remediation</label>
        
        <label><input id="in-scope" type="checkbox" checked /> Only in-scope</label>
        <button id="refresh-db">Refresh DB</button>
        <button id="expand-all">Expand All</button>
        <button id="collapse-all">Collapse All</button>
      </div>
      <div class="toolbar-row2">
      <button id="live-toggle">Enable Live scanning</button>
        <button id="scan">Manual scan</button>
        <label>Scan last <input id="limit" type="number" min="0" value="100" /> requests (0 = all)</label>
      </div>
    </div>

    <div class="legend">
      <span class="legend-label">Legend:</span>
      <span class="legend-item high">🔥 High – critical impact</span>
      <span class="legend-item medium">⚠️ Medium – important</span>
      <span class="legend-item low">ℹ️ Low – informational</span>
    </div>

    <div id="summary" class="summary">Ready.</div>
    <div id="results" class="results"></div>
  `;

  root.appendChild(panel);

  sdk.navigation.addPage("/retirejs", { body: root });
  sdk.sidebar.registerItem("RetireJS Scanner", "/retirejs");

  //
  // DOM refs
  //

  const resultsEl = root.querySelector("#results");
  const summaryEl = root.querySelector("#summary");
  const searchEl = root.querySelector("#search");

  const autoExpandEl = root.querySelector("#auto-expand");
  const autoFindingsEl = root.querySelector("#auto-findings");
  const showSummariesEl = root.querySelector("#show-summaries");
  const limitEl = root.querySelector("#limit");
  const inScopeEl = root.querySelector("#in-scope");

  const refreshDbBtn = root.querySelector("#refresh-db");
  const expandAllBtn = root.querySelector("#expand-all");
  const collapseAllBtn = root.querySelector("#collapse-all");
  const scanBtn = root.querySelector("#scan");
  const liveToggleBtn = root.querySelector("#live-toggle");

  let liveEnabled = false;

  function updateLiveButtonLabel() {
    if (liveEnabled) {
      liveToggleBtn.textContent = "Stop Live scanning";
      liveToggleBtn.classList.add("live-on");
    } else {
      liveToggleBtn.textContent = "Enable Live scanning";
      liveToggleBtn.classList.remove("live-on");
    }
  }

  //
  // Load prefs into UI
  //

  const prefs = getPrefs();
  autoExpandEl.checked = !!prefs.autoExpandHighs;
  autoFindingsEl.checked = !!prefs.autoCreateFindings;
  showSummariesEl.checked =
    typeof prefs.showSummaries === "boolean" ? prefs.showSummaries : true;
  limitEl.value = prefs.limit ?? 100;
  inScopeEl.checked = !!prefs.inScopeOnly;
  searchEl.value = prefs.query || "";

  async function persistPrefs() {
    const parsedLimit = parseInt(limitEl.value ?? "100", 10);
    const next = {
      autoExpandHighs: autoExpandEl.checked,
      autoCreateFindings: autoFindingsEl.checked,
      showSummaries: showSummariesEl.checked,
      limit: Number.isFinite(parsedLimit) && parsedLimit >= 0 ? parsedLimit : 100,
      inScopeOnly: inScopeEl.checked,
      query: searchEl.value || "",
    };
    await savePrefs(next);
  }

  [autoExpandEl, autoFindingsEl, showSummariesEl, limitEl, inScopeEl, searchEl].forEach(
    (el) => {
      el.addEventListener("change", persistPrefs);
      el.addEventListener("keyup", persistPrefs);
    }
  );

  //
  // Filtering + controls
  //

  function applySearchFilter() {
    const q = (searchEl.value || "").toLowerCase();
    for (const details of resultsEl.querySelectorAll("details.accordion")) {
      const url = details.getAttribute("data-url") || "";
      const libs = details.getAttribute("data-libs") || "";
      const match = url.includes(q) || libs.includes(q);
      details.style.display = match ? "" : "none";
    }
  }

  searchEl.addEventListener("input", applySearchFilter);

  refreshDbBtn.addEventListener("click", async () => {
    summaryEl.textContent = "Refreshing DB...";
    try {
      await loadDb(true);
      summaryEl.textContent = "DB refreshed.";
    } catch (e) {
      summaryEl.textContent = "DB refresh failed: " + e.message;
    }
  });

  expandAllBtn.addEventListener("click", () => {
    resultsEl.querySelectorAll("details.accordion").forEach((d) => (d.open = true));
  });

  collapseAllBtn.addEventListener("click", () => {
    resultsEl.querySelectorAll("details.accordion").forEach((d) => (d.open = false));
  });

  //
  // Live scanning toggle
  //

  updateLiveButtonLabel();

  liveToggleBtn.addEventListener("click", async () => {
    try {
      const db = await loadDb();
      liveEnabled = !liveEnabled;
      await sdk.backend.toggleLiveScanning(db, liveEnabled, inScopeEl.checked);
      updateLiveButtonLabel();
      summaryEl.textContent = liveEnabled
        ? "Live RetireJS scanning enabled (Findings will be created as responses arrive)."
        : "Live RetireJS scanning disabled.";
    } catch (e) {
      liveEnabled = false;
      updateLiveButtonLabel();
      summaryEl.textContent = "Failed to toggle live scanning: " + e.message;
    }
  });

  // If live is enabled and user changes scope, update backend
  inScopeEl.addEventListener("change", async () => {
    if (!liveEnabled) return;
    try {
      const db = await loadDb();
      await sdk.backend.toggleLiveScanning(db, true, inScopeEl.checked);
    } catch (e) {
      summaryEl.textContent =
        "Failed to update live scanning scope: " + e.message;
    }
  });

  //
  // Main scan (batch)
  //

  async function runScan() {
    let loading = resultsEl.querySelector(".loading-overlay");
    if (!loading) {
      loading = document.createElement("div");
      loading.className = "loading-overlay";
      loading.innerHTML = `
        <div class="spinner"></div>
        <div class="loading-text">Scanning captured JavaScript...</div>
      `;
      resultsEl.appendChild(loading);
    }

    try {
      summaryEl.textContent = "Loading DB...";
      const db = await loadDb();

      summaryEl.textContent = "Scanning...";

      const parsedLimit = parseInt(limitEl.value ?? "100", 10);
      const options = {
        limit:
          Number.isFinite(parsedLimit) && parsedLimit >= 0
            ? parsedLimit
            : 100,
        inScopeOnly: inScopeEl.checked,
        autoCreateFindings: autoFindingsEl.checked,
      };

      const { results, counts } = await sdk.backend.scanCapturedJavaScript(
        db,
        options
      );

      summaryEl.textContent = `Scanned: ${counts.scanned} | Vulnerable files: ${counts.files} | High: ${counts.high} | Medium: ${counts.medium} | Low: ${counts.low}`;

      resultsEl.innerHTML = "";

      results.forEach((r) => {
        const highest = highestSeverity(r.findings);
        const d = document.createElement("details");
        d.className = "accordion " + highest;
        d.setAttribute("data-url", r.url.toLowerCase());
        d.setAttribute(
          "data-libs",
          r.findings.map((f) => f.libName.toLowerCase()).join(" ")
        );
        if (autoExpandEl.checked && highest === "high") d.open = true;

        const s = document.createElement("summary");
        s.innerHTML = `
          <span class="sev ${highest}">${severityIcon(highest)}</span>
          <span class="path" title="${r.url}">${r.url}</span>
          <span class="count">${r.findings.length} libs</span>
        `;
        d.appendChild(s);

        const inner = document.createElement("div");
        inner.className = "inner";

        r.findings.forEach((f) => {
          const card = document.createElement("div");
          card.className = "lib-card " + f.severity;

          const ver = f.version ? ` v${f.version}` : "";
          const reason = f.reason
            ? `<div class="reason">🧠 ${f.reason}</div>`
            : "";

          const rawDetails =
            f.vulnDetails && Array.isArray(f.vulnDetails) && f.vulnDetails.length
              ? f.vulnDetails
              : (f.vulns || []).map((summary) => ({
                  summary,
                  severity: f.severity,
                  refs: [],
                }));

          // sort by severity: high → medium → low
          const sevOrder = { high: 3, medium: 2, low: 1 };
          const vulnDetails = rawDetails.slice().sort((a, b) => {
            const sa = sevOrder[(a.severity || "low").toLowerCase()] || 0;
            const sb = sevOrder[(b.severity || "low").toLowerCase()] || 0;
            return sb - sa;
          });

          //  compute Summary + Remediation data 
          let highCount = 0,
            medCount = 0,
            lowCount = 0;
          let sampleHigh = null,
            sampleMed = null,
            sampleLow = null;
          let minBelow = null;
          let minAtOrAbove = null;

          vulnDetails.forEach((vd) => {
            const sev = (vd.severity || f.severity || "low").toLowerCase();
            if (sev === "high") {
              highCount++;
              if (!sampleHigh) sampleHigh = vd.summary;
            } else if (sev === "medium") {
              medCount++;
              if (!sampleMed) sampleMed = vd.summary;
            } else {
              lowCount++;
              if (!sampleLow) sampleLow = vd.summary;
            }

            if (vd.below) {
              if (!minBelow || compareVersions(vd.below, minBelow) < 0) {
                minBelow = vd.below;
              }
            }
            if (vd.atOrAbove) {
              if (!minAtOrAbove || compareVersions(vd.atOrAbove, minAtOrAbove) < 0) {
                minAtOrAbove = vd.atOrAbove;
              }
            }
          });

          const totalVulns = highCount + medCount + lowCount;
          let summaryLine = `Uses ${f.libName}${ver} with ${totalVulns} known vulnerabilities (High: ${highCount}, Medium: ${medCount}, Low: ${lowCount}).`;
          const highestExample = sampleHigh || sampleMed || sampleLow;
          if (highestExample) {
            summaryLine += ` Highest impact: ${highestExample}`;
          }

          let remediationLine = "";
          if (minBelow) {
            remediationLine = `Upgrade ${f.libName} to at least v${minBelow} (or the latest stable release) to address these issues.`;
          } else if (minAtOrAbove) {
            remediationLine = `Upgrade ${f.libName} to a version newer than v${minAtOrAbove} (ideally the latest stable release) to reduce risk.`;
          } else {
            remediationLine = `Review the references and upgrade to the latest stable version of ${f.libName} where possible.`;
          }

          const fileSummaryHtml = `<div class="file-summary"><strong>Summary:</strong> ${summaryLine}</div>`;
          const remediationHtml = `<div class="file-remediation"><strong>Remediation:</strong> ${remediationLine}</div>`;

          const showSummaries = showSummariesEl.checked;

          let bodyHtml = reason;
          if (showSummaries) {
            bodyHtml += fileSummaryHtml + remediationHtml;
          }

          const vulnRefsSet = new Set();

          vulnDetails.forEach((vd) => {
            const refs = (vd.refs || []).filter(Boolean);
            refs.forEach((u) => vulnRefsSet.add(u));

            if (refs.length > 0) {
              bodyHtml += `
                <details class="vuln-details">
                  <summary>${vd.summary}</summary>
                  <div class="refs">
                    ${refs
                      .map((u) => `<a href="${u}" target="_blank">${u}</a>`)
                      .join("<br>")}
                  </div>
                </details>
              `;
            } else {
              bodyHtml += `<div class="desc">${vd.summary}</div>`;
            }
          });

          const extraRefs = (f.references || []).filter(
            (u) => !vulnRefsSet.has(u)
          );
          if (extraRefs.length > 0) {
            bodyHtml += `
              <details class="vuln-details further">
                <summary>Further information</summary>
                <div class="refs">
                  ${extraRefs
                    .map((u) => `<a href="${u}" target="_blank">${u}</a>`)
                    .join("<br>")}
                </div>
              </details>
            `;
          }

          card.innerHTML = `
            <div class="lib-head">
              <span class="lib-name">${f.libName}${ver}</span>
              <span class="badge ${f.severity}">${f.severity.toUpperCase()}</span>
            </div>
            <div class="lib-body">
              ${bodyHtml}
            </div>
          `;

          inner.appendChild(card);
        });

        d.appendChild(inner);
        resultsEl.appendChild(d);
      });

      applySearchFilter();
    } catch (e) {
      summaryEl.textContent = "Scan failed: " + e.message;
    } finally {
      const currentOverlay = resultsEl.querySelector(".loading-overlay");
      if (currentOverlay) {
        currentOverlay.remove();
      }
    }
  }

  scanBtn.addEventListener("click", runScan);
  


};


