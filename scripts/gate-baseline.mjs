// Shared baseline logic of the governance code checks (docs/development/GOVERNANCE.md §4.2): size-budget,
// check-charter, check-vendor-pins. A gate collects findings as { key: value } (value = a number, e.g. a line count,
// or `true`); this module compares them with the repository's baseline `.governance/<gate>.json` and decides the exit
// code. Rollout (GW5): while `today <= reportOnlyUntil` (or no baseline exists) the gate only reports; afterwards it
// fails on a finding that is not in the baseline or whose number grew. The baseline only shrinks: `--update-baseline`
// removes fixed entries and lowers numbers, `--init` (re)writes it in full and starts the report-only week.
// Canonical copy: agentteam-deployments scripts/gate-baseline.mjs; every repository runs a byte-identical copy.
// Justification: (Open source first) no maintained tool keeps a shrink-only baseline across heterogeneous checks;
// ESLint bulk suppressions cover ESLint rules only and the checks here are not ESLint rules.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const REPORT_DAYS = 7;
export const baselinePath = (root, gate) => join(root, ".governance", `${gate}.json`);

export function loadBaseline(root, gate) {
  const path = baselinePath(root, gate);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`${gate}: cannot read baseline ${path}: ${error.message}. Fix the JSON or regenerate it with --init.`);
  }
}

/** Pure: the date (YYYY-MM-DD) `days` after `today`. */
export function addDays(today, days) {
  const date = new Date(`${today}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

/** Pure: compare findings with a baseline. Returns { added, grew, fixed, shrunk, enforcing }. */
export function compare(findings, baseline, today) {
  const known = baseline?.findings ?? {};
  const added = [];
  const grew = [];
  const fixed = [];
  const shrunk = [];
  for (const [key, value] of Object.entries(findings)) {
    if (!(key in known)) added.push(key);
    else if (typeof value === "number" && typeof known[key] === "number") {
      if (value > known[key]) grew.push(key);
      else if (value < known[key]) shrunk.push(key);
    }
  }
  for (const key of Object.keys(known)) if (!(key in findings)) fixed.push(key);
  const enforcing = Boolean(baseline?.reportOnlyUntil) && today > baseline.reportOnlyUntil;
  return { added, grew, fixed, shrunk, enforcing };
}

/** Pure: the baseline after `--update-baseline`: fixed entries removed, numbers lowered, nothing added or raised. */
export function ratchet(findings, baseline) {
  const next = {};
  for (const [key, old] of Object.entries(baseline.findings ?? {})) {
    if (!(key in findings)) continue;
    next[key] = typeof old === "number" && typeof findings[key] === "number" ? Math.min(old, findings[key]) : old;
  }
  return { ...baseline, findings: next };
}

/** Pure: the gate-specific settings of a baseline (everything but the fields this module owns), kept by `--init`. */
export const extrasOf = (baseline) =>
  Object.fromEntries(Object.entries(baseline ?? {}).filter(([key]) => !["gate", "mode", "reportOnlyUntil", "updated", "findings"].includes(key)));

const sorted = (object) => Object.fromEntries(Object.entries(object).sort(([a], [b]) => a.localeCompare(b)));

/**
 * Run a gate. `describe(key, value, baselineValue)` words one finding; `hint` is the closing advice.
 * Returns the process exit code.
 */
export function finish({ gate, root, findings, argv, today = new Date().toISOString().slice(0, 10), describe, hint, scanned }) {
  const baseline = loadBaseline(root, gate);
  const path = baselinePath(root, gate);
  const write = (value) => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify({ ...value, findings: sorted(value.findings) }, null, 2)}\n`);
  };
  if (argv.includes("--init")) {
    write({ gate, mode: "report-only-then-fail-on-new", reportOnlyUntil: addDays(today, REPORT_DAYS), updated: today, ...extrasOf(baseline), findings });
    console.log(`${gate}: baseline written to .governance/${gate}.json (${Object.keys(findings).length} findings), report-only until ${addDays(today, REPORT_DAYS)}`);
    return 0;
  }
  if (argv.includes("--update-baseline")) {
    if (!baseline) {
      console.error(`${gate}: no baseline to update; create it with --init`);
      return 1;
    }
    const next = ratchet(findings, baseline);
    write({ ...next, updated: today });
    console.log(`${gate}: baseline shrunk to ${Object.keys(next.findings).length} findings`);
    return 0;
  }
  const result = compare(findings, baseline, today);
  const bad = [...result.added, ...result.grew].sort();
  for (const key of bad) console.error(`${gate}: ${describe(key, findings[key], baseline?.findings?.[key])}`);
  const total = Object.keys(findings).length;
  const known = Object.keys(baseline?.findings ?? {}).length;
  const notes = [];
  if (result.fixed.length || result.shrunk.length) notes.push(`${result.fixed.length + result.shrunk.length} baseline entries can shrink (run with --update-baseline)`);
  const summary = `${total} finding(s), ${known} in the baseline, ${bad.length} new${scanned ? ` (${scanned})` : ""}`;
  if (!baseline) {
    console.log(`${gate}: report-only, no baseline yet; ${summary}. Create it with --init.`);
    return 0;
  }
  if (bad.length === 0) {
    console.log(`${gate}: ok, ${summary}${notes.length ? `; ${notes.join("; ")}` : ""}`);
    return 0;
  }
  if (!result.enforcing) {
    console.log(`${gate}: report-only until ${baseline.reportOnlyUntil}; after that these fail the check. ${summary}. ${hint}`);
    return 0;
  }
  console.error(`${gate}: ${summary}. ${hint}`);
  return 1;
}
