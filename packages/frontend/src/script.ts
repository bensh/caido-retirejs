import type { FrontendSDK } from "./types";

type SeverityLabel = "low" | "medium" | "high";

interface Preferences {
  autoExpandHighs: boolean;
  autoCreateFindings: boolean;
  showSummaries: boolean;
  limit: number;
  inScopeOnly: boolean;
  query: string;
}

type ScanOptions = Parameters<
  FrontendSDK["backend"]["scanCapturedJavaScript"]
>[1];

type BackendRepo = Parameters<
  FrontendSDK["backend"]["scanCapturedJavaScript"]
>[0];

type ScanResponse = Awaited<
  ReturnType<FrontendSDK["backend"]["scanCapturedJavaScript"]>
>;

type ScanResultEntry = ScanResponse["results"][number];
type RetireFinding = ScanResultEntry["findings"][number];
type BackendVulnDetail =
  RetireFinding["vulnDetails"] extends Array<infer Item> ? Item : never;
type FallbackVulnSummary =
  RetireFinding["vulns"] extends Array<infer Item> ? Item : string;

interface NormalizedVulnDetail {
  summary: string;
  severity: SeverityLabel;
  refs: string[];
  below?: string;
  atOrAbove?: string;
}

const severityRank: Record<SeverityLabel, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

const normalizeSeverity = (value?: string): SeverityLabel => {
  const normalized = (value ?? "low").toLowerCase();
  if (normalized === "high" || normalized === "medium") {
    return normalized;
  }
  return "low";
};

const getErrorMessage = (error: unknown): string => {
  if (error instanceof Error) {
    return error.message;
  }
  return typeof error === "string" ? error : JSON.stringify(error);
};

const sanitizeRefs = (refs?: unknown[]): string[] => {
  if (!Array.isArray(refs)) return [];
  return refs
    .filter((item): item is string => typeof item === "string" && !!item.length)
    .map((item) => item.trim());
};

const normalizeVulnDetails = (
  finding: RetireFinding,
): NormalizedVulnDetail[] => {
  const rawDetails = finding.vulnDetails as BackendVulnDetail[] | undefined;
  if (Array.isArray(rawDetails) && rawDetails.length > 0) {
    return rawDetails.map((vd: BackendVulnDetail) => ({
      summary: vd.summary,
      severity: normalizeSeverity(vd.severity || finding.severity),
      refs: sanitizeRefs(vd.refs),
      below: typeof vd.below === "string" ? vd.below : undefined,
      atOrAbove: typeof vd.atOrAbove === "string" ? vd.atOrAbove : undefined,
    }));
  }

  const summaries = Array.isArray(finding.vulns) ? finding.vulns : [];
  return summaries.map((summary: FallbackVulnSummary) => ({
    summary: String(summary),
    severity: normalizeSeverity(finding.severity),
    refs: [],
  }));
};

export const init = (sdk: FrontendSDK): void => {
  const RETIRE_DB_URL =
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json";

  //
  // Helpers
  //

  function compareVersions(a?: string | number, b?: string | number): number {
    if (typeof a === "undefined" || typeof b === "undefined") return 0;
    const pa = String(a)
      .split(/[^0-9a-zA-Z]+/)
      .filter(Boolean);
    const pb = String(b)
      .split(/[^0-9a-zA-Z]+/)
      .filter(Boolean);
    const n = Math.max(pa.length, pb.length);
    for (let i = 0; i < n; i++) {
      const va = pa[i] ?? "0";
      const vb = pb[i] ?? "0";
      const na = /^\d+$/.test(va) ? parseInt(va, 10) : va;
      const nb = /^\d+$/.test(vb) ? parseInt(vb, 10) : vb;
      if (na > nb) return 1;
      if (na < nb) return -1;
    }
    return 0;
  }

  let cachedRepo: BackendRepo | undefined;

  function getPrefs(): Preferences {
    const stored = sdk.storage.get() as Partial<Preferences> | undefined;
    const defaults: Preferences = {
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

  async function savePrefs(next: Partial<Preferences>): Promise<void> {
    const existing =
      (sdk.storage.get() as Partial<Preferences> | undefined) || {};
    await sdk.storage.set({ ...existing, ...next });
  }

  async function loadDb(force = false): Promise<BackendRepo> {
    if (cachedRepo && !force) return cachedRepo;

    // eslint-disable-next-line compat/compat
    const res = await fetch(RETIRE_DB_URL);
    if (!res.ok) throw new Error("Failed to fetch Retire.js DB");
    const db = (await res.json()) as BackendRepo;
    cachedRepo = db;
    return db;
  }

  function severityIcon(sev: string): string {
    const normalized = normalizeSeverity(sev);
    if (normalized === "high") return "🔥";
    if (normalized === "medium") return "⚠️";
    if (normalized === "low") return "ℹ️";
    return "🧱";
  }

  function highestSeverity(findings: RetireFinding[]): SeverityLabel {
    let hasHigh = false;
    let hasMed = false;
    for (const f of findings) {
      const sev = normalizeSeverity(f.severity);
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
  root.id = "plugin--retire-js";

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

  const getElement = <T extends Element>(selector: string): T => {
    const el = root.querySelector(selector);
    if (!el) {
      throw new Error(`RetireJS UI missing element: ${selector}`);
    }
    return el as T;
  };

  const resultsEl = getElement<HTMLDivElement>("#results");
  const summaryEl = getElement<HTMLDivElement>("#summary");
  const searchEl = getElement<HTMLInputElement>("#search");

  const autoExpandEl = getElement<HTMLInputElement>("#auto-expand");
  const autoFindingsEl = getElement<HTMLInputElement>("#auto-findings");
  const showSummariesEl = getElement<HTMLInputElement>("#show-summaries");
  const limitEl = getElement<HTMLInputElement>("#limit");
  const inScopeEl = getElement<HTMLInputElement>("#in-scope");

  const refreshDbBtn = getElement<HTMLButtonElement>("#refresh-db");
  const expandAllBtn = getElement<HTMLButtonElement>("#expand-all");
  const collapseAllBtn = getElement<HTMLButtonElement>("#collapse-all");
  const scanBtn = getElement<HTMLButtonElement>("#scan");
  const liveToggleBtn = getElement<HTMLButtonElement>("#live-toggle");

  let liveEnabled = false;

  function updateLiveButtonLabel(): void {
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
  limitEl.value = String(prefs.limit ?? 100);
  inScopeEl.checked = !!prefs.inScopeOnly;
  searchEl.value = prefs.query || "";

  async function persistPrefs(): Promise<void> {
    const parsedLimit = parseInt(limitEl.value || "100", 10);
    const next: Preferences = {
      autoExpandHighs: autoExpandEl.checked,
      autoCreateFindings: autoFindingsEl.checked,
      showSummaries: showSummariesEl.checked,
      limit:
        Number.isFinite(parsedLimit) && parsedLimit >= 0 ? parsedLimit : 100,
      inScopeOnly: inScopeEl.checked,
      query: searchEl.value || "",
    };
    await savePrefs(next);
  }

  const prefInputs: HTMLInputElement[] = [
    autoExpandEl,
    autoFindingsEl,
    showSummariesEl,
    limitEl,
    inScopeEl,
    searchEl,
  ];

  prefInputs.forEach((el) => {
    el.addEventListener("change", persistPrefs);
    el.addEventListener("keyup", persistPrefs);
  });

  //
  // Filtering + controls
  //

  function applySearchFilter(): void {
    const q = (searchEl.value ?? "").toLowerCase();
    const accordions = Array.from(
      resultsEl.querySelectorAll<HTMLDetailsElement>("details.accordion"),
    );
    for (const details of accordions) {
      const url = details.getAttribute("data-url") ?? "";
      const libs = details.getAttribute("data-libs") ?? "";
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
      summaryEl.textContent = "DB refresh failed: " + getErrorMessage(e);
    }
  });

  expandAllBtn.addEventListener("click", () => {
    const accordions = Array.from(
      resultsEl.querySelectorAll<HTMLDetailsElement>("details.accordion"),
    );
    accordions.forEach((d) => {
      d.open = true;
    });
  });

  collapseAllBtn.addEventListener("click", () => {
    const accordions = Array.from(
      resultsEl.querySelectorAll<HTMLDetailsElement>("details.accordion"),
    );
    accordions.forEach((d) => {
      d.open = false;
    });
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
      summaryEl.textContent =
        "Failed to toggle live scanning: " + getErrorMessage(e);
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
        "Failed to update live scanning scope: " + getErrorMessage(e);
    }
  });

  //
  // Main scan (batch)
  //

  async function runScan(): Promise<void> {
    let loading = resultsEl.querySelector<HTMLDivElement>(".loading-overlay");
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

      const parsedLimit = parseInt(limitEl.value || "100", 10);
      const options: NonNullable<ScanOptions> = {
        limit:
          Number.isFinite(parsedLimit) && parsedLimit >= 0 ? parsedLimit : 100,
        inScopeOnly: inScopeEl.checked,
        autoCreateFindings: autoFindingsEl.checked,
      };

      const { results, counts } = await sdk.backend.scanCapturedJavaScript(
        db,
        options,
      );

      summaryEl.textContent = `Scanned: ${counts.scanned} | Vulnerable files: ${counts.files} | High: ${counts.high} | Medium: ${counts.medium} | Low: ${counts.low}`;

      resultsEl.innerHTML = "";

      const typedResults = results ?? [];
      typedResults.forEach((r: ScanResultEntry) => {
        const highest = highestSeverity(r.findings);
        const detailsEl = document.createElement("details");
        detailsEl.className = "accordion " + highest;
        detailsEl.setAttribute("data-url", r.url.toLowerCase());
        detailsEl.setAttribute(
          "data-libs",
          r.findings.map((f) => f.libName.toLowerCase()).join(" "),
        );
        if (autoExpandEl.checked && highest === "high") detailsEl.open = true;

        const summary = document.createElement("summary");
        summary.innerHTML = `
          <span class="sev ${highest}">${severityIcon(highest)}</span>
          <span class="path" title="${r.url}">${r.url}</span>
          <span class="count">${r.findings.length} libs</span>
        `;
        detailsEl.appendChild(summary);

        const inner = document.createElement("div");
        inner.className = "inner";

        const findings = r.findings ?? [];
        findings.forEach((f: RetireFinding) => {
          const card = document.createElement("div");
          card.className = "lib-card " + f.severity;

          const ver = f.version ? ` v${f.version}` : "";
          const reason = f.reason
            ? `<div class="reason">🧠 ${f.reason}</div>`
            : "";

          const vulnDetails = normalizeVulnDetails(f).sort(
            (a: NormalizedVulnDetail, b: NormalizedVulnDetail) =>
              severityRank[normalizeSeverity(b.severity)] -
              severityRank[normalizeSeverity(a.severity)],
          );

          let highCount = 0,
            medCount = 0,
            lowCount = 0;
          let sampleHigh: string | undefined;
          let sampleMed: string | undefined;
          let sampleLow: string | undefined;
          let minBelow: string | undefined;
          let minAtOrAbove: string | undefined;

          vulnDetails.forEach((vd: NormalizedVulnDetail) => {
            const sev = normalizeSeverity(vd.severity || f.severity);
            if (sev === "high") {
              highCount++;
              if (sampleHigh === undefined) sampleHigh = vd.summary;
            } else if (sev === "medium") {
              medCount++;
              if (sampleMed === undefined) sampleMed = vd.summary;
            } else {
              lowCount++;
              if (sampleLow === undefined) sampleLow = vd.summary;
            }

            const vdBelow = vd.below;
            if (typeof vdBelow === "string" && vdBelow.length > 0) {
              if (
                minBelow === undefined ||
                compareVersions(vdBelow, minBelow) < 0
              ) {
                minBelow = vdBelow;
              }
            }
            const vdAtOrAbove = vd.atOrAbove;
            if (typeof vdAtOrAbove === "string" && vdAtOrAbove.length > 0) {
              if (
                minAtOrAbove === undefined ||
                compareVersions(vdAtOrAbove, minAtOrAbove) < 0
              ) {
                minAtOrAbove = vdAtOrAbove;
              }
            }
          });

          const totalVulns = highCount + medCount + lowCount;
          let summaryLine = `Uses ${f.libName}${ver} with ${totalVulns} known vulnerabilities (High: ${highCount}, Medium: ${medCount}, Low: ${lowCount}).`;
          const highestExample = sampleHigh ?? sampleMed ?? sampleLow;
          if (typeof highestExample === "string" && highestExample.length > 0) {
            summaryLine += ` Highest impact: ${highestExample}`;
          }

          let remediationLine = "";
          if (typeof minBelow === "string" && minBelow.length > 0) {
            remediationLine = `Upgrade ${f.libName} to at least v${minBelow} (or the latest stable release) to address these issues.`;
          } else if (
            typeof minAtOrAbove === "string" &&
            minAtOrAbove.length > 0
          ) {
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

          const vulnRefsSet = new Set<string>();

          vulnDetails.forEach((vd: NormalizedVulnDetail) => {
            const refs = vd.refs ?? [];
            refs.forEach((u: string) => vulnRefsSet.add(u));

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

          const referenceList = Array.isArray(f.references) ? f.references : [];
          const extraRefs = referenceList.filter(
            (u: string) => !!u && !vulnRefsSet.has(u),
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

        detailsEl.appendChild(inner);
        resultsEl.appendChild(detailsEl);
      });

      applySearchFilter();
    } catch (e) {
      summaryEl.textContent = "Scan failed: " + getErrorMessage(e);
    } finally {
      const currentOverlay =
        resultsEl.querySelector<HTMLDivElement>(".loading-overlay");
      if (currentOverlay) {
        currentOverlay.remove();
      }
    }
  }

  scanBtn.addEventListener("click", runScan);
};
