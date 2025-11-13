const processedFindingKeys = new Set<string>();

export function init(sdk) {
  //
  // === Retire.js core logic (adapted from node/lib/retire.js) ===
  //
  
  function makeDedupeKey(
  mode: "manual" | "live",
  request: any,
  libName: string,
  version: string
) {
  const host = request && request.getHost ? request.getHost() : "";
  const path = request && request.getPath ? request.getPath() : "";
  return `${mode}|${host}${path}|${libName}|${version}`;
}

  function isDefined(o) {
    return typeof o !== "undefined";
  }

  function uniq(results) {
    const keys = {};
    return results.filter((r) => {
      const k = r.component + " " + r.version + " " + r.detection;
      keys[k] = keys[k] || 0;
      return keys[k]++ === 0;
    });
  }

  function normalizeVersionPlaceholder(regex) {
    return regex.replace(/§§version§§/g, "[0-9][0-9.a-z_\\-]+");
  }

  function simpleMatch(regex, data) {
    const pattern = normalizeVersionPlaceholder(regex);
    const re = new RegExp(pattern, "g");
    const result = [];
    let match;
    while ((match = re.exec(data))) {
      if (match.length > 1 && match[1]) {
        result.push(match[1]);
      } else {
        result.push(match[0]);
      }
    }
    return result;
  }

  function replacementMatch(regex, data) {
    const pattern = normalizeVersionPlaceholder(regex);
    const ar = /^\/(.*[^\\])\/([^/]+)\/$/.exec(pattern);
    if (!ar) return [];
    const re = new RegExp(ar[1], "g");
    const result = [];
    let match;
    while ((match = re.exec(data))) {
      if (match) {
        const ver = match[0].replace(new RegExp(ar[1]), ar[2]);
        result.push(ver);
      }
    }
    return result;
  }

  function splitAndMatchAll(tokenizer) {
    return function (regex, data) {
      const pattern = normalizeVersionPlaceholder(regex);
      const elm = data.split(tokenizer).pop();
      return simpleMatch("^" + pattern + "$", elm);
    };
  }

  function scan(data, extractor, repo, matcher) {
    const detected = [];
    const m = matcher || simpleMatch;

    for (const component in repo) {
      if (!Object.prototype.hasOwnProperty.call(repo, component)) continue;
      const exRoot = repo[component].extractors || {};
      const extractors = exRoot[extractor];
      if (!isDefined(extractors)) continue;

      for (const i in extractors) {
        const regex = extractors[i];
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

  function scanhash(hash, repo) {
    const out = [];
    for (const component in repo) {
      if (!Object.prototype.hasOwnProperty.call(repo, component)) continue;
      const exRoot = repo[component].extractors || {};
      const hashes = exRoot.hashes;
      if (!isDefined(hashes)) continue;
      if (Object.prototype.hasOwnProperty.call(hashes, hash)) {
        out.push({
          version: hashes[hash],
          component,
          detection: "hash",
        });
      }
    }
    return out;
  }

  function toComparable(n) {
    if (!isDefined(n)) return 0;
    if (String(n).match(/^[0-9]+$/)) {
      return parseInt(n, 10);
    }
    return n;
  }

  function isAtOrAbove(version1, version2) {
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

  function check(results, repo) {
    for (let r = 0; r < results.length; r++) {
      const result = results[r];
      const entry = repo[result.component];
      if (!entry) continue;

      const vulns = entry.vulnerabilities || [];
      result.vulnerabilities = result.vulnerabilities || [];

      for (let i = 0; i < vulns.length; i++) {
        const v = vulns[i];

        if (!isDefined(v.below) || !isAtOrAbove(result.version, v.below)) {
          if (isDefined(v.atOrAbove) && !isAtOrAbove(result.version, v.atOrAbove)) {
            continue;
          }

          const vulnerability = {
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

  function scanUri(uri, repo) {
    const result = scan(uri, "uri", repo);
    return check(result, repo);
  }

  function scanFileName(fileName, repo, includeUri) {
    let result = scan(fileName, "filename", repo, splitAndMatchAll(/[\/\\]/));
    if (includeUri) {
      result = result.concat(
        scan(fileName.replace(/\\/g, "/"), "uri", repo)
      );
    }
    return check(result, repo);
  }

  function scanFileContent(content, repo, hasher) {
    const normalizedContent = content.toString().replace(/(\r\n|\r)/g, "\n");
    let result = scan(normalizedContent, "filecontent", repo);
    if (result.length === 0) {
      result = scan(
        normalizedContent,
        "filecontentreplace",
        repo,
        replacementMatch
      );
    }
    if (result.length === 0 && hasher && hasher.sha1) {
      result = scanhash(hasher.sha1(normalizedContent), repo);
    }
    return check(result, repo);
  }

  function highestSeverity(vulns) {
    const order = { low: 1, medium: 2, high: 3 };
    let best = "low";
    let score = 0;
    for (const v of vulns || []) {
      const sev = (v.severity || "low").toLowerCase();
      const s = order[sev] || 1;
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

 let liveRepo = null;
  let liveEnabled = false;
  let liveInScopeOnly = true;

function mergeResultsByUrl(rawResults) {
  const byUrl = new Map();

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
            (f.severity || "").toLowerCase()
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
    async (_callSdk, repo, options) => {
      options = options || {};
      const limit =
        typeof options.limit === "number" && options.limit >= 0
          ? options.limit
          : 100;
      const inScopeOnly = !!options.inScopeOnly;
      const autoCreateFindings = !!options.autoCreateFindings;

      if (!repo || typeof repo !== "object") {
        return {
          results: [],
          counts: { scanned: 0, files: 0, high: 0, medium: 0, low: 0 },
        };
      }

      const rawResults = [];
      //const processedFindingKeys = new Set();

      let fetched = 0;
      let cursor = undefined;
      const batchSize = 100;

      while (limit === 0 || fetched < limit) {
        const toFetch =
          limit === 0 ? batchSize : Math.min(batchSize, limit - fetched);

        let q = sdk.requests
          .query()
          .descending("req", "created_at");

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

          const reqUrl = request && request.getUrl ? request.getUrl() : "";
          const respUrl =
            response && response.getUrl ? response.getUrl() : reqUrl;

          const headers = response.getHeaders
            ? response.getHeaders()
            : {};
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
          const detections = [];

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
          const perLibMap = new Map();
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
            for (const v of det.vulnerabilities) {
              rec.vulns.push({ v, detection: det.detection });
            }
          }

          const findings = [];
          for (const [, rec] of perLibMap.entries()) {
            const allVulnObjs = rec.vulns.map((x) => x.v);
            const severity = highestSeverity(allVulnObjs);

            const vulnDetails = [];
            const allRefsSet = new Set();
            let minBelow = null;
            let minAtOrAbove = null;

            for (const { v } of rec.vulns) {
              const infoArr = Array.isArray(v.info)
                ? v.info
                : v.info
                ? [v.info]
                : [];

              const urlRefs = infoArr.filter((s) =>
                /^https?:\/\//i.test(String(s))
              );
              const nonUrlInfo = infoArr.filter(
                (s) => !/^https?:\/\//i.test(String(s))
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

            const findingRecord = {
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
    const dedupeKey = makeDedupeKey("manual", request, rec.libName, rec.version);

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
        `Detected ${rec.libName} v${rec.version} with known vulnerabilities via RetireJS pattern matching.`
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
        `RetireJS plugin: error creating batch finding: ${err}`
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
const order = { low: 0, medium: 1, high: 2 };

for (const r of results) {
  let maxSev = "low";
  for (const f of r.findings) {
    const sev = (f.severity || "low").toLowerCase();
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

    }
  );

  //
  //  Toggle live scanning (called from frontend) 
  //

  sdk.api.register(
    "toggleLiveScanning",
    async (_callSdk, repo, enabled, inScopeOnly) => {
      if (repo && typeof repo === "object") {
        liveRepo = repo;
      }
      liveEnabled = !!enabled;
      liveInScopeOnly = !!inScopeOnly;
      return { enabled: liveEnabled };
    }
  );

  //
  //  Live scanner: runs on every intercepted response when enabled 
  //

  sdk.events.onInterceptResponse(
    async (callSdk, request, response) => {
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

        const reqUrl = request && request.getUrl ? request.getUrl() : "";
        const respUrl =
          response && response.getUrl ? response.getUrl() : reqUrl;

        const headers = response.getHeaders
          ? response.getHeaders()
          : {};
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
        const detections = [];

        detections.push(...scanUri(urlForDisplay, liveRepo));
        detections.push(...scanFileName(urlForDisplay, liveRepo, true));
        if (bodyText && bodyText.length) {
          detections.push(...scanFileContent(bodyText, liveRepo));
        }

        if (detections.length === 0) return;

        const perLibMap = new Map();
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
          for (const v of det.vulnerabilities) {
            rec.vulns.push({ v, detection: det.detection });
          }
        }

        for (const [, rec] of perLibMap.entries()) {
          const allVulnObjs = rec.vulns.map((x) => x.v);
          const severity = highestSeverity(allVulnObjs);

          const vulnDetails = [];
          const allRefsSet = new Set();
          let minBelow = null;
          let minAtOrAbove = null;

          for (const { v } of rec.vulns) {
            const infoArr = Array.isArray(v.info)
              ? v.info
              : v.info
              ? [v.info]
              : [];

            const urlRefs = infoArr.filter((s) =>
              /^https?:\/\//i.test(String(s))
            );
            const nonUrlInfo = infoArr.filter(
              (s) => !/^https?:\/\//i.test(String(s))
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
    const dedupeKey = makeDedupeKey("live", request, rec.libName, rec.version);

    if (processedFindingKeys.has(dedupeKey)) {
      // We already created a live finding for this exact host/path/lib/version
      continue; // move to next library in perLibMap
    }

    processedFindingKeys.add(dedupeKey);

    const lines: string[] = [];
    lines.push(
      `Detected ${rec.libName} v${rec.version} with known vulnerabilities via RetireJS (live scan).`
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
        `RetireJS plugin: error creating live finding: ${err}`
      );
  }
}

        }
      } catch (err) {
        sdk.console &&
          sdk.console.error &&
          sdk.console.error(
            `RetireJS plugin: live scanner error: ${String(err)}`
          );
        }
    }
  );
}
