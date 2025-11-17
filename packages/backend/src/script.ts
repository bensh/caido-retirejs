import type { SDK } from "caido:plugin";

type SeverityLabel = "low" | "medium" | "high";

interface RetireVulnerability {
  info?: string | string[];
  below?: string;
  atOrAbove?: string;
  severity?: string;
  identifiers?: Record<string, unknown>;
  cwe?: string | string[];
}

type ExtractorGroup = ReadonlyArray<string> | Record<string, string>;
type ExtractorName = "uri" | "filename" | "filecontent" | "filecontentreplace";

interface RetireExtractors {
  uri?: ExtractorGroup;
  filename?: ExtractorGroup;
  filecontent?: ExtractorGroup;
  filecontentreplace?: ExtractorGroup;
  hashes?: Record<string, string>;
}

interface RetireLibrary {
  vulnerabilities?: RetireVulnerability[];
  extractors?: RetireExtractors;
}

type RetireRepo = Record<string, RetireLibrary>;

type Matcher = (regex: string, data: string) => string[];

interface DetectionResult {
  component: string;
  version: string;
  detection: string;
  vulnerabilities?: RetireVulnerability[];
}

interface HashProvider {
  sha1?: (data: string) => string;
}

interface VulnDetail {
  summary: string;
  severity: string;
  refs: string[];
  below: string | null;
  atOrAbove: string | null;
}

interface RetireFinding {
  libName: string;
  version: string;
  severity: SeverityLabel;
  reason: string;
  vulns: string[];
  vulnDetails: VulnDetail[];
  references: string[];
  minBelow: string | null;
  minAtOrAbove: string | null;
}

interface ScanResultEntry {
  url: string;
  findings: RetireFinding[];
}

interface ScanCounts {
  scanned: number;
  files: number;
  high: number;
  medium: number;
  low: number;
}

interface ScanCapturedOptions {
  limit?: number;
  inScopeOnly?: boolean;
  autoCreateFindings?: boolean;
}

interface ToggleState {
  enabled: boolean;
}

type RequestLike = {
  getHost?: () => string | null | undefined;
  getPath?: () => string | null | undefined;
  getId?: () => string | null | undefined;
  getUrl?: () => string | null | undefined;
};

interface PerLibAccumulation {
  libName: string;
  version: string;
  vulns: Array<{ v: RetireVulnerability; detection: string }>;
}

export interface RetireAPI extends Record<string, (...args: any[]) => any> {
  scanCapturedJavaScript: (
    repo: RetireRepo,
    options?: ScanCapturedOptions,
  ) => Promise<{ results: ScanResultEntry[]; counts: ScanCounts }>;
  toggleLiveScanning: (
    repo: RetireRepo,
    enabled?: boolean,
    inScopeOnly?: boolean,
  ) => Promise<ToggleState>;
}

const processedFindingKeys = new Set<string>();

export function init(sdk: SDK<RetireAPI>): void {
  //
  // === Retire.js core logic (adapted from node/lib/retire.js) ===
  //
  function makeDedupeKey(
    mode: "manual" | "live",
    request: RequestLike | null | undefined,
    libName: string,
    version: string,
  ): string {
    const host = request?.getHost?.() ?? "";
    const path = request?.getPath?.() ?? "";
    return `${mode}|${host}${path}|${libName}|${version}`;
  }

  function isDefined<T>(o: T | undefined): o is T {
    return typeof o !== "undefined";
  }

  function uniq(results: DetectionResult[]): DetectionResult[] {
    const keys: Record<string, number> = {};
    return results.filter((r) => {
      const k = r.component + " " + r.version + " " + r.detection;
      keys[k] = keys[k] || 0;
      return keys[k]++ === 0;
    });
  }

  function normalizeVersionPlaceholder(regex: string): string {
    return regex.replace(/§§version§§/g, "[0-9][0-9.a-z_\\-]+");
  }

  function simpleMatch(regex: string, data: string): string[] {
    const pattern = normalizeVersionPlaceholder(regex);
    const re = new RegExp(pattern, "g");
    const result: string[] = [];
    let match: RegExpExecArray | null;
    while ((match = re.exec(data))) {
      if (match.length > 1 && match[1]) {
        result.push(match[1]);
      } else {
        result.push(match[0]);
      }
    }
    return result;
  }

  function replacementMatch(regex: string, data: string): string[] {
    const pattern = normalizeVersionPlaceholder(regex);
    const ar = /^\/(.*[^\\])\/([^/]+)\/$/.exec(pattern);
    if (!ar) return [];
    const [, body = "", replacement = ""] = ar;
    const re = new RegExp(body, "g");
    const result: string[] = [];
    let match: RegExpExecArray | null;
    while ((match = re.exec(data))) {
      if (match) {
        const ver = match[0].replace(new RegExp(body), replacement);
        result.push(ver);
      }
    }
    return result;
  }

  function splitAndMatchAll(tokenizer: RegExp | string): Matcher {
    return function (regex: string, data: string): string[] {
      const pattern = normalizeVersionPlaceholder(regex);
      const elm = data.split(tokenizer).pop() ?? "";
      return simpleMatch("^" + pattern + "$", elm);
    };
  }

  function scan(
    data: string,
    extractor: ExtractorName,
    repo: RetireRepo,
    matcher?: Matcher,
  ): DetectionResult[] {
    const detected: DetectionResult[] = [];
    const m: Matcher = matcher || simpleMatch;

    for (const component in repo) {
      if (!Object.prototype.hasOwnProperty.call(repo, component)) continue;
      const library = repo[component];
      if (!library) continue;
      const exRoot = library.extractors || {};
      const extractors = exRoot[extractor];
      if (!isDefined(extractors)) continue;

      const patterns = Array.isArray(extractors)
        ? extractors
        : Object.values(extractors);

      for (const regex of patterns) {
        const matches = m(regex, data);
        matches.forEach((match) => {
          if (!match) return;
          const version = String(match).replace(/(\.|-)min$/, "");
          detected.push({
            version,
            component,
            detection: extractor,
          });
        });
      }
    }
    return uniq(detected);
  }

  function scanhash(hash: string, repo: RetireRepo): DetectionResult[] {
    const out: DetectionResult[] = [];
    for (const component in repo) {
      if (!Object.prototype.hasOwnProperty.call(repo, component)) continue;
      const library = repo[component];
      if (!library) continue;
      const exRoot = library.extractors || {};
      const hashes = exRoot.hashes;
      if (!isDefined(hashes)) continue;
      if (Object.prototype.hasOwnProperty.call(hashes, hash)) {
        const version = hashes[hash];
        if (!version) continue;
        out.push({
          version,
          component,
          detection: "hash",
        });
      }
    }
    return out;
  }

  function toComparable(n: string | number | undefined): string | number {
    if (!isDefined(n)) return 0;
    if (String(n).match(/^[0-9]+$/)) {
      return parseInt(String(n), 10);
    }
    return n;
  }

  function isAtOrAbove(
    version1: string | number,
    version2: string | number,
  ): boolean {
    const v1 = String(version1).split(/[.\-]/g);
    const v2 = String(version2).split(/[.\-]/g);
    const l = v1.length > v2.length ? v1.length : v2.length;

    for (let i = 0; i < l; i++) {
      const v1_c = toComparable(v1[i]);
      const v2_c = toComparable(v2[i]);

      if (typeof v1_c !== typeof v2_c) {
        return typeof v1_c === "number";
      }
      if (v1_c > v2_c) return true;
      if (v1_c < v2_c) return false;
    }
    return true;
  }

  function check(
    results: DetectionResult[],
    repo: RetireRepo,
  ): DetectionResult[] {
    for (let r = 0; r < results.length; r++) {
      const result = results[r];
      if (!result) continue;
      const entry = repo[result.component];
      if (!entry) continue;

      const vulns = entry.vulnerabilities || [];
      result.vulnerabilities = result.vulnerabilities || [];

      for (let i = 0; i < vulns.length; i++) {
        const v = vulns[i];
        if (!v) continue;

        if (!isDefined(v.below) || !isAtOrAbove(result.version, v.below)) {
          if (
            isDefined(v.atOrAbove) &&
            !isAtOrAbove(result.version, v.atOrAbove)
          ) {
            continue;
          }

          const vulnerability: RetireVulnerability = {
            info: v.info,
            below: v.below,
            atOrAbove: v.atOrAbove,
          };

          if (v.severity) vulnerability.severity = v.severity;
          if (v.identifiers) vulnerability.identifiers = v.identifiers;
          if (v.cwe) vulnerability.cwe = v.cwe;

          result.vulnerabilities.push(vulnerability);
        }
      }
    }
    return results;
  }

  function scanUri(uri: string, repo: RetireRepo): DetectionResult[] {
    const result = scan(uri, "uri", repo);
    return check(result, repo);
  }

  function scanFileName(
    fileName: string,
    repo: RetireRepo,
    includeUri?: boolean,
  ): DetectionResult[] {
    let result = scan(fileName, "filename", repo, splitAndMatchAll(/[\/\\]/));
    if (includeUri) {
      result = result.concat(scan(fileName.replace(/\\/g, "/"), "uri", repo));
    }
    return check(result, repo);
  }

  function scanFileContent(
    content: string,
    repo: RetireRepo,
    hasher?: HashProvider,
  ): DetectionResult[] {
    const normalizedContent = content.toString().replace(/(\r\n|\r)/g, "\n");
    let result = scan(normalizedContent, "filecontent", repo);
    if (result.length === 0) {
      result = scan(
        normalizedContent,
        "filecontentreplace",
        repo,
        replacementMatch,
      );
    }
    if (result.length === 0 && hasher && hasher.sha1) {
      result = scanhash(hasher.sha1(normalizedContent), repo);
    }
    return check(result, repo);
  }

  function highestSeverity(vulns?: RetireVulnerability[]): SeverityLabel {
    const order: Record<SeverityLabel, number> = { low: 1, medium: 2, high: 3 };
    let best: SeverityLabel = "low";
    let score = 0;
    for (const v of vulns || []) {
      const sevRaw = (v.severity || "low").toLowerCase();
      const sev: SeverityLabel =
        sevRaw === "high" || sevRaw === "medium" || sevRaw === "low"
          ? (sevRaw as SeverityLabel)
          : "low";
      const s = order[sev];
      if (s > score) {
        score = s;
        best = sev;
      }
    }
    return best;
  }

  //
  // === Live scanning state ===
  //

  let liveRepo: RetireRepo | null = null;
  let liveEnabled = false;
  let liveInScopeOnly = true;

  function mergeResultsByUrl(rawResults: ScanResultEntry[]): ScanResultEntry[] {
    const byUrl = new Map<string, ScanResultEntry>();

    for (const entry of rawResults) {
      if (!entry || !entry.url) continue;
      const url = entry.url;
      let existing = byUrl.get(url);

      if (!existing) {
        existing = { url, findings: [] };
        byUrl.set(url, existing);
      }

      for (const f of entry.findings || []) {
        const already = existing.findings.some(
          (ef) =>
            ef.libName === f.libName &&
            ef.version === f.version &&
            (ef.severity || "").toLowerCase() ===
              (f.severity || "").toLowerCase(),
        );
        if (!already) {
          existing.findings.push(f);
        }
      }
    }

    return Array.from(byUrl.values());
  }

  //
  // === Batch scanner API ===
  //

  sdk.api.register(
    "scanCapturedJavaScript",
    async (
      _callSdk: SDK<RetireAPI>,
      repo: RetireRepo,
      options?: ScanCapturedOptions,
    ) => {
      const opts = options ?? {};
      const limit =
        typeof opts.limit === "number" && opts.limit >= 0 ? opts.limit : 100;
      const inScopeOnly = !!opts.inScopeOnly;
      const autoCreateFindings = !!opts.autoCreateFindings;

      if (!repo || typeof repo !== "object") {
        return {
          results: [],
          counts: { scanned: 0, files: 0, high: 0, medium: 0, low: 0 },
        };
      }

      const rawResults: ScanResultEntry[] = [];

      let fetched = 0;
      let cursor: string | undefined;
      const batchSize = 100;

      while (limit === 0 || fetched < limit) {
        const toFetch =
          limit === 0 ? batchSize : Math.min(batchSize, limit - fetched);

        let q = sdk.requests.query().descending("req", "created_at");

        if (cursor) {
          q = q.after(cursor);
        }

        const page = await q.first(toFetch).execute();
        const items = (page && page.items) || [];
        if (items.length === 0) {
          break; // no more history
        }
        for (const item of items) {
          const request = item.request;
          const response = item.response;
          if (!response) continue;

          if (inScopeOnly) {
            try {
              if (!sdk.requests.inScope(request)) continue;
            } catch {
              // ignore scope errors
            }
          }

          const reqLike = request as RequestLike | undefined;
          const respLike = response as RequestLike | undefined;
          const reqUrl = reqLike?.getUrl?.() ?? "";
          const respUrl = respLike?.getUrl?.() ?? reqUrl;

          const headers = response.getHeaders ? response.getHeaders() : {};
          const ct =
            (headers["Content-Type"] && headers["Content-Type"][0]) ||
            (headers["content-type"] && headers["content-type"][0]) ||
            "";
          const ctLower = ct.toLowerCase();

          if (
            !ctLower.includes("javascript") &&
            !respUrl.toLowerCase().endsWith(".js") &&
            !reqUrl.toLowerCase().endsWith(".js")
          ) {
            continue;
          }

          const bodyObj = response.getBody ? response.getBody() : null;
          const bodyText = bodyObj ? await bodyObj.toText() : "";
          const urlForDisplay = respUrl || reqUrl || "(unknown)";
          const detections: DetectionResult[] = [];

          // Retire.js-style detection: URL, filename, body
          detections.push(...scanUri(urlForDisplay, repo));
          detections.push(...scanFileName(urlForDisplay, repo, true));
          if (bodyText && bodyText.length) {
            detections.push(...scanFileContent(bodyText, repo));
          }

          if (detections.length === 0) {
            continue;
          }
          // Aggregate per library+version for this request/response
          const perLibMap = new Map<string, PerLibAccumulation>();
          for (const det of detections) {
            if (!det.vulnerabilities || det.vulnerabilities.length === 0) {
              continue;
            }
            const key = det.component + "|" + det.version;
            if (!perLibMap.has(key)) {
              perLibMap.set(key, {
                libName: det.component,
                version: det.version,
                vulns: [],
              });
            }
            const rec = perLibMap.get(key);
            if (!rec) continue;
            for (const v of det.vulnerabilities) {
              rec.vulns.push({ v, detection: det.detection });
            }
          }

          const findings: RetireFinding[] = [];
          for (const [, rec] of perLibMap.entries()) {
            const allVulnObjs = rec.vulns.map((x) => x.v);
            const severity = highestSeverity(allVulnObjs);

            const vulnDetails: VulnDetail[] = [];
            const allRefsSet = new Set<string>();
            let minBelow: string | null = null;
            let minAtOrAbove: string | null = null;

            for (const { v } of rec.vulns) {
              const infoArr = Array.isArray(v.info)
                ? v.info
                : v.info
                  ? [v.info]
                  : [];

              const urlRefs = infoArr.filter((s) =>
                /^https?:\/\//i.test(String(s)),
              );
              const nonUrlInfo = infoArr.filter(
                (s) => !/^https?:\/\//i.test(String(s)),
              );

              urlRefs.forEach((u) => allRefsSet.add(u));

              const sevLabel = (v.severity || severity || "low").toUpperCase();
              const belowStr = v.below ? ` (< ${v.below})` : "";
              const atOrAboveStr = v.atOrAbove ? ` (>= ${v.atOrAbove})` : "";
              const baseSummary =
                nonUrlInfo[0] || urlRefs[0] || "Known vulnerability";

              const summary = `${sevLabel}: ${baseSummary}${belowStr}${atOrAboveStr}`;

              if (v.below) {
                if (!minBelow || isAtOrAbove(minBelow, v.below)) {
                  minBelow = v.below;
                }
              }
              if (v.atOrAbove) {
                if (!minAtOrAbove || isAtOrAbove(minAtOrAbove, v.atOrAbove)) {
                  minAtOrAbove = v.atOrAbove;
                }
              }

              vulnDetails.push({
                summary,
                severity: v.severity || severity,
                refs: urlRefs,
                below: v.below || null,
                atOrAbove: v.atOrAbove || null,
              });
            }

            const refsAll = Array.from(allRefsSet);
            const reason = `Detected via RetireJS pattern matching.`;

            const findingRecord: RetireFinding = {
              libName: rec.libName,
              version: rec.version,
              severity,
              reason,
              vulns: vulnDetails.map((d) => d.summary),
              vulnDetails,
              references: refsAll,
              minBelow,
              minAtOrAbove,
            };

            findings.push(findingRecord);

            // === Auto-create Caido Finding (batch mode) ===
            if (autoCreateFindings && sdk.findings && sdk.findings.create) {
              try {
                const dedupeKey = makeDedupeKey(
                  "manual",
                  request,
                  rec.libName,
                  rec.version,
                );

                let exists = false;

                if (sdk.findings.exists) {
                  try {
                    exists = await sdk.findings.exists(dedupeKey);
                  } catch {
                    exists = false;
                  }
                }

                if (!exists && processedFindingKeys.has(dedupeKey)) {
                  exists = true;
                }

                if (!exists) {
                  processedFindingKeys.add(dedupeKey);

                  const lines: string[] = [];
                  lines.push(
                    `Detected ${rec.libName} v${rec.version} with known vulnerabilities via RetireJS pattern matching.`,
                  );
                  lines.push("");
                  lines.push("Vulnerabilities:");
                  for (const vd of vulnDetails) {
                    lines.push(`- ${vd.summary}`);
                  }

                  let remediation = "";
                  if (minBelow) {
                    remediation = `Upgrade ${rec.libName} to at least v${minBelow} (or the latest stable release) to address these issues.`;
                  } else if (minAtOrAbove) {
                    remediation = `Upgrade ${rec.libName} to a version newer than v${minAtOrAbove} (ideally the latest stable release) to reduce risk.`;
                  } else {
                    remediation = `Review the references and upgrade to the latest stable version of ${rec.libName} where possible.`;
                  }

                  lines.push("");
                  lines.push("Remediation:");
                  lines.push(`- ${remediation}`);

                  lines.push("");
                  lines.push("Context:");
                  lines.push(`- URL: ${urlForDisplay}`);
                  if (request && request.getId) {
                    lines.push(`- Request ID: ${request.getId()}`);
                  }
                  if (response && response.getCode) {
                    lines.push(`- Response code: ${response.getCode()}`);
                  }

                  if (refsAll.length > 0) {
                    lines.push("");
                    lines.push("References:");
                    for (const u of refsAll) {
                      lines.push(`- ${u}`);
                    }
                  }

                  await sdk.findings.create({
                    title: `${rec.libName} v${rec.version} - ${severity.toUpperCase()}`,
                    description: lines.join("\n"),
                    reporter: "RetireJS (Manual)",
                    request,
                    dedupeKey,
                  });
                }
              } catch (err) {
                sdk.console &&
                  sdk.console.error &&
                  sdk.console.error(
                    `RetireJS plugin: error creating batch finding: ${err}`,
                  );
              }
            }
          }

          if (findings.length > 0) {
            rawResults.push({
              url: urlForDisplay,
              findings,
            });
          }
        }

        fetched += items.length;

        if (limit !== 0 && fetched >= limit) {
          break;
        }

        if (items.length < toFetch) {
          break;
        }

        const pageInfo = (page && page.pageInfo) || {};
        if (!pageInfo.endCursor) {
          break;
        }
        cursor = pageInfo.endCursor;
      }

      /// --- Deduplicate results by URL ---
      const results = mergeResultsByUrl(rawResults);

      let high = 0,
        medium = 0,
        low = 0;
      const order: Record<SeverityLabel, number> = {
        low: 0,
        medium: 1,
        high: 2,
      };

      for (const r of results) {
        let maxSev: SeverityLabel = "low";
        for (const f of r.findings) {
          const sev = f.severity;
          if (order[sev] > order[maxSev]) maxSev = sev;
        }
        if (maxSev === "high") high++;
        else if (maxSev === "medium") medium++;
        else low++;
      }

      return {
        results,
        counts: {
          scanned: fetched,
          files: results.length,
          high,
          medium,
          low,
        },
      };
    },
  );

  //
  //  Toggle live scanning (called from frontend)
  //

  sdk.api.register(
    "toggleLiveScanning",
    async (
      _callSdk: SDK<RetireAPI>,
      repo: RetireRepo,
      enabled?: boolean,
      inScopeOnly?: boolean,
    ): Promise<ToggleState> => {
      if (repo && typeof repo === "object") {
        liveRepo = repo;
      }
      liveEnabled = !!enabled;
      liveInScopeOnly = !!inScopeOnly;
      return { enabled: liveEnabled };
    },
  );

  //
  //  Live scanner: runs on every intercepted response when enabled
  //

  sdk.events.onInterceptResponse(async (callSdk, request, response) => {
    try {
      if (!liveEnabled || !liveRepo) return;

      // Only in-scope if configured
      if (liveInScopeOnly && callSdk.requests && callSdk.requests.inScope) {
        try {
          if (!callSdk.requests.inScope(request)) return;
        } catch {
          // if inScope throws, fall back to scanning everything
        }
      }

      const reqLike = request as RequestLike | undefined;
      const respLike = response as RequestLike | undefined;
      const reqUrl = reqLike?.getUrl?.() ?? "";
      const respUrl = respLike?.getUrl?.() ?? reqUrl;

      const headers = response.getHeaders ? response.getHeaders() : {};
      const ct =
        (headers["Content-Type"] && headers["Content-Type"][0]) ||
        (headers["content-type"] && headers["content-type"][0]) ||
        "";
      const ctLower = ct.toLowerCase();

      if (
        !ctLower.includes("javascript") &&
        !respUrl.toLowerCase().endsWith(".js") &&
        !reqUrl.toLowerCase().endsWith(".js")
      ) {
        return;
      }

      const bodyObj = response.getBody ? response.getBody() : null;
      const bodyText = bodyObj ? await bodyObj.toText() : "";

      const urlForDisplay = respUrl || reqUrl || "(unknown)";
      const detections: DetectionResult[] = [];

      detections.push(...scanUri(urlForDisplay, liveRepo));
      detections.push(...scanFileName(urlForDisplay, liveRepo, true));
      if (bodyText && bodyText.length) {
        detections.push(...scanFileContent(bodyText, liveRepo));
      }

      if (detections.length === 0) return;

      const perLibMap = new Map<string, PerLibAccumulation>();
      for (const det of detections) {
        if (!det.vulnerabilities || det.vulnerabilities.length === 0) {
          continue;
        }
        const key = det.component + "|" + det.version;
        if (!perLibMap.has(key)) {
          perLibMap.set(key, {
            libName: det.component,
            version: det.version,
            vulns: [],
          });
        }
        const rec = perLibMap.get(key);
        if (!rec) continue;
        for (const v of det.vulnerabilities) {
          rec.vulns.push({ v, detection: det.detection });
        }
      }

      for (const [, rec] of perLibMap.entries()) {
        const allVulnObjs = rec.vulns.map((x) => x.v);
        const severity = highestSeverity(allVulnObjs);

        const vulnDetails: VulnDetail[] = [];
        const allRefsSet = new Set<string>();
        let minBelow: string | null = null;
        let minAtOrAbove: string | null = null;

        for (const { v } of rec.vulns) {
          const infoArr = Array.isArray(v.info)
            ? v.info
            : v.info
              ? [v.info]
              : [];

          const urlRefs = infoArr.filter((s) =>
            /^https?:\/\//i.test(String(s)),
          );
          const nonUrlInfo = infoArr.filter(
            (s) => !/^https?:\/\//i.test(String(s)),
          );

          urlRefs.forEach((u) => allRefsSet.add(u));

          const sevLabel = (v.severity || severity || "low").toUpperCase();
          const belowStr = v.below ? ` (< ${v.below})` : "";
          const atOrAboveStr = v.atOrAbove ? ` (>= ${v.atOrAbove})` : "";
          const baseSummary =
            nonUrlInfo[0] || urlRefs[0] || "Known vulnerability";

          const summary = `${sevLabel}: ${baseSummary}${belowStr}${atOrAboveStr}`;

          if (v.below) {
            if (!minBelow || isAtOrAbove(minBelow, v.below)) {
              minBelow = v.below;
            }
          }
          if (v.atOrAbove) {
            if (!minAtOrAbove || isAtOrAbove(minAtOrAbove, v.atOrAbove)) {
              minAtOrAbove = v.atOrAbove;
            }
          }

          vulnDetails.push({
            summary,
            severity: v.severity || severity,
            refs: urlRefs,
            below: v.below || null,
            atOrAbove: v.atOrAbove || null,
          });
        }

        const refsAll = Array.from(allRefsSet);

        if (callSdk.findings && callSdk.findings.create) {
          try {
            // One live finding per host+path+lib+version per plugin session
            const dedupeKey = makeDedupeKey(
              "live",
              request,
              rec.libName,
              rec.version,
            );

            if (processedFindingKeys.has(dedupeKey)) {
              // We already created a live finding for this exact host/path/lib/version
              continue; // move to next library in perLibMap
            }

            processedFindingKeys.add(dedupeKey);

            const lines: string[] = [];
            lines.push(
              `Detected ${rec.libName} v${rec.version} with known vulnerabilities via RetireJS (live scan).`,
            );
            lines.push("");
            lines.push("Vulnerabilities:");
            for (const vd of vulnDetails) {
              lines.push(`- ${vd.summary}`);
            }

            let remediation = "";
            if (minBelow) {
              remediation = `Upgrade ${rec.libName} to at least v${minBelow} (or the latest stable release) to address these issues.`;
            } else if (minAtOrAbove) {
              remediation = `Upgrade ${rec.libName} to a version newer than v${minAtOrAbove} (ideally the latest stable release) to reduce risk.`;
            } else {
              remediation = `Review the references and upgrade to the latest stable version of ${rec.libName} where possible.`;
            }

            lines.push("");
            lines.push("Remediation:");
            lines.push(`- ${remediation}`);

            lines.push("");
            lines.push("Context:");
            lines.push(`- URL: ${urlForDisplay}`);
            if (request && request.getId) {
              lines.push(`- Request ID: ${request.getId()}`);
            }
            if (response && response.getCode) {
              lines.push(`- Response code: ${response.getCode()}`);
            }

            if (refsAll.length > 0) {
              lines.push("");
              lines.push("References:");
              for (const u of refsAll) {
                lines.push(`- ${u}`);
              }
            }

            await callSdk.findings.create({
              title: `${rec.libName} v${rec.version} - ${severity.toUpperCase()}`,
              description: lines.join("\n"),
              reporter: "RetireJS (Live)",
              request,
              dedupeKey,
            });
          } catch (err) {
            callSdk.console &&
              callSdk.console.error &&
              callSdk.console.error(
                `RetireJS plugin: error creating live finding: ${err}`,
              );
          }
        }
      }
    } catch (err) {
      sdk.console &&
        sdk.console.error &&
        sdk.console.error(
          `RetireJS plugin: live scanner error: ${String(err)}`,
        );
    }
  });
}
