#!/usr/bin/env node
// Kernel / provider boundary check (agentteam-deployments docs/development/GOVERNANCE.md GL11; ADR 0003 §3; owner
// 2026-11-12 「这样的话，内核和供应商需要做好区分。感觉这里很多密钥」, then 「密钥收敛是不是也可以推进」). Only the kernel
// (R69: AgentIdentity, AgentSpace, AgentEvents, AgentCompute, AgentSecrets, agentrouter-newapi) holds service
// identities, reaches kernel components in-network, and handles NewAPI administrator tokens; nobody but the operator
// reads the platform's shared deploy secrets; only AgentCompute obtains `aud: netbird`. Findings, counted per file:
//
//   service-identity   an STS service identity (svc_<layer>) or an STS service-key file in a repository that is not
//                      kernel; in AgentIdentity, a SERVICES / service-key entry for a non-kernel service
//   act-for            in AgentIdentity, act-for granted to any service but newapi (ADR 0001 §2.7: svc_newapi alone)
//   kernel-in-network  an in-network address of a kernel component (a URL host without a dot) outside the kernel
//   platform-secret    a read of the platform's shared deploy secret (the Coolify root token) outside operations
//   newapi-admin-token a NewAPI administrator / access token outside the kernel
//   netbird-audience   an `aud: netbird` request (or, in AgentIdentity's STS configuration, a grant of it) outside
//                      AgentCompute
//
// Repository classes: kernel, operations (agentteam-deployments, resident-ci, agent-foundation, github-runners: none
// of the rules), everyone else (all rules). The class comes from the git remote, or `"repository"` in the baseline.
// Comment lines, Markdown, tests, fixtures, vendored and built files are not read. Baseline
// `.governance/check-kernel-boundary.json`: today's findings, shrink-only, report-only for the first week after
// `--init` (scripts/gate-baseline.mjs). Extra: `"ignore": ["<path prefix>"]`. Seconds, no install, no network.
//
//   node scripts/check-kernel-boundary.mjs [--init | --update-baseline]
//
// Canonical copy: agentteam-deployments scripts/check-kernel-boundary.mjs; every repository runs a byte-identical copy
// next to gate-baseline.mjs. Justification: (Open source first, #477) built on the shared gate framework
// (gate-baseline.mjs) like check-sdk-only, not on Semgrep CE (LGPL-2.1) or ast-grep (MIT): the shared gates run with no
// install in every repository and language (TypeScript, Go, Python, shell, JSON, YAML, Compose), and every rule here is
// lexical (a host name, an identifier, a file name), so syntax trees add nothing; the rules are data (RULES below) and
// can be translated to ast-grep rules if a structural rule is ever needed.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { finish, loadBaseline } from "./gate-baseline.mjs";

export const GATE = "check-kernel-boundary";
export const KERNEL = ["agentrouter-top/agentidentity", "agentrouter-top/agentspace", "agentrouter-top/agentevents",
  "agentrouter-top/agentcompute", "agentrouter-top/agentsecrets", "agentrouter-top/agentrouter-newapi"];
export const OPERATIONS = ["agentrouter-top/agentteam-deployments", "agentrouter-top/resident-ci",
  "agentrouter-top/agent-foundation", "agentrouter-top/github-runners"];
const KERNEL_SERVICES = ["newapi", "agentspace", "agentevents", "agentcompute", "agentsecrets", "agentidentity", "operator"];
const COMPONENT = "(?:agentidentity|agentspace|agentevents|agentcompute|agentsecrets|agentrouter-newapi|newapi)";

/** The rules, as data: id, the repository classes it applies to, the pattern (global, counted per line). */
export const RULES = [
  { id: "service-identity", classes: ["other"],
    re: /\bsvc_(?:newapi|agent[a-z]+|ecs|operator|judge)\b|\b[A-Z_]*IDENTITY[A-Z_]*SERVICE_KEY[A-Z_]*\b|\bSERVICE_KEY_FILE\b/gu },
  { id: "kernel-in-network", classes: ["other"], re: new RegExp(`https?://${COMPONENT}[a-z0-9-]*(?![a-z0-9.-])`, "gu") },
  { id: "platform-secret", classes: ["kernel", "other"], re: /coolify-api-token/gu },
  { id: "newapi-admin-token", classes: ["other"], re: /newapi[_-]?(?:admin|access)[_-]?token|NEWAPI_ADMIN_TOKEN|newApi(?:Admin|Access)Token/giu },
  { id: "netbird-audience", classes: ["kernel", "other"], except: ["agentrouter-top/agentcompute"],
    re: /\b(?:aud|audience)["']?\s*[:=]\s*["']netbird["']/giu },
];

const TEXT = /\.(?:[cm]?[jt]sx?|py|go|rs|sh|bash|json|ya?ml|toml|env|conf|ini|tf|hcl|vue|svelte)$|(?:^|\/)(?:Dockerfile[^/]*|Containerfile|Makefile|\.env[^/]*)$/u;
const SKIP = /(?:^|\/)(?:node_modules|vendor|third_party|dist|build|target|coverage|\.next|fixtures?|testdata|testing|acceptance|vectors|examples|__snapshots__|__pycache__|\.governance|tests?|e2e|docs)\/|\.(?:test|spec)\.[^/]+$|_test\.go$|\.d\.ts$|\.min\.|\.generated\.|(?:^|\/)generated\.[a-z]+$|(?:^|\/)(?:package-lock|pnpm-lock|yarn)\.[a-z]+$|go\.sum$|(?:^|\/)check-kernel-boundary(?:\.test)?\.mjs$/u;

/** Pure: does the gate read this file? */
export const scanned = (file, ignore = []) => TEXT.test(file) && !SKIP.test(file) && !ignore.some((p) => file.startsWith(p));

/** Pure: is this line a comment (by the file's language)? */
export function commentLine(file, line) {
  const t = line.trimStart();
  if (/\.(?:py|sh|bash|ya?ml|toml|env|conf|ini|tf|hcl)$|(?:^|\/)(?:Dockerfile[^/]*|Makefile|\.env[^/]*)$/u.test(file)) return t.startsWith("#");
  return t.startsWith("//") || t.startsWith("/*") || t.startsWith("*");
}

/** Pure: the line without a trailing comment (`  // …` or `  # …` after code; never the `//` of a URL). */
export function codeOf(file, line) {
  const hash = /\.(?:py|sh|bash|ya?ml|toml|env|conf|ini|tf|hcl)$|(?:^|\/)(?:Dockerfile[^/]*|Makefile|\.env[^/]*)$/u.test(file);
  return hash ? line.replace(/\s#\s.*$/u, "") : line.replace(/\s\/\/\s.*$/u, "");
}

/** Pure: kernel | operations | other, for `owner/name`. */
export const classOf = (repository) => (KERNEL.includes(repository) ? "kernel" : OPERATIONS.includes(repository) ? "operations" : "other");

const count = (re, line) => {
  re.lastIndex = 0;
  let n = 0;
  while (re.exec(line)) n += 1;
  return n;
};

/** Pure: AgentIdentity's STS configuration — non-kernel services and act-for on any service but newapi. */
export function stsFindings(file, text) {
  const out = [];
  const lines = text.split("\n");
  if (/(?:^|\/)deploy\/sts-config\.py$/u.test(file)) {
    let inServices = false;
    let current = null;
    lines.forEach((line, index) => {
      if (/^SERVICES\s*=\s*\{/u.test(line)) inServices = true;
      else if (inServices && /^\}/u.test(line)) inServices = false;
      else if (inServices && !commentLine(file, line)) {
        const head = /^\s{4}"([a-z]+)":\s*\{/u.exec(line);
        if (head) {
          current = head[1];
          if (!KERNEL_SERVICES.includes(current)) out.push({ rule: "service-identity", item: current, line: index + 1 });
        }
        if (current && current !== "newapi" && /"act_for_scopes"/u.test(line)) out.push({ rule: "act-for", item: current, line: index + 1 });
        if (current && current !== "agentcompute" && /"netbird"/u.test(line)) out.push({ rule: "netbird-audience", item: current, line: index + 1 });
      }
    });
    // People's applications' ceilings (CEILINGS) granting aud netbird to an application.
    let inCeilings = false;
    let app = null;
    lines.forEach((line, index) => {
      if (/^CEILINGS\s*=\s*\{/u.test(line)) inCeilings = true;
      else if (inCeilings && /^\}/u.test(line)) inCeilings = false;
      else if (inCeilings && !commentLine(file, line)) {
        const head = /^\s{4}"([a-z]+)":\s*\{/u.exec(line);
        if (head) app = head[1];
        if (app && /"netbird"\s*:/u.test(line)) out.push({ rule: "netbird-audience", item: `ceiling ${app}`, line: index + 1 });
      }
    });
  }
  if (/(?:^|\/)deploy\/service-keys\.py$/u.test(file)) {
    lines.forEach((line, index) => {
      if (commentLine(file, line)) return;
      const service = /"service":\s*"([a-z]+)"/u.exec(line)?.[1];
      if (!service) return;
      if (!KERNEL_SERVICES.includes(service)) out.push({ rule: "service-identity", item: service, line: index + 1 });
      if (service !== "newapi" && /"act_for":\s*True/u.test(line)) out.push({ rule: "act-for", item: service, line: index + 1 });
    });
  }
  return out;
}

/**
 * Pure core. `repository` = `owner/name` (lower-case), `files` = { path: text }.
 * Returns { findings: { key: count }, examples: { key: "line N: text" } }.
 */
export function boundaryFindings({ repository, files }) {
  const cls = classOf(repository);
  const findings = {};
  const examples = {};
  const add = (key, n, example) => {
    findings[key] = (findings[key] ?? 0) + n;
    examples[key] ??= example;
  };
  if (cls === "operations") return { findings, examples };
  for (const [file, text] of Object.entries(files)) {
    if (text.includes("\u0000")) continue;
    if (repository === "agentrouter-top/agentidentity") {
      for (const f of stsFindings(file, text)) add(`${f.rule}: ${file} (${f.item})`, 1, `line ${f.line}`);
    }
    const lines = text.split("\n");
    for (const rule of RULES) {
      if (!rule.classes.includes(cls) || rule.except?.includes(repository)) continue;
      lines.forEach((line, index) => {
        if (commentLine(file, line)) return;
        const n = count(rule.re, codeOf(file, line));
        if (n) add(`${rule.id}: ${file}`, n, `line ${index + 1}: ${line.trim().slice(0, 120)}`);
      });
    }
  }
  return { findings, examples };
}

/** Pure: `owner/name` of a git remote URL (https or ssh), lower-case; null when it is none. */
export const repositoryOf = (url) => /github\.com[:/]([\w.-]+\/[\w.-]+?)(?:\.git)?\/?$/u.exec(url.trim())?.[1]?.toLowerCase() ?? null;

function trackedFiles(root) {
  const result = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard"], { cwd: root, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(`${GATE}: git ls-files failed in ${root}: ${result.stderr.trim()}`);
  return result.stdout.split("\n").filter(Boolean);
}

function main(argv) {
  const root = spawnSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).stdout.trim() || process.cwd();
  const baseline = loadBaseline(root, GATE);
  const remote = repositoryOf(spawnSync("git", ["config", "--get", "remote.origin.url"], { cwd: root, encoding: "utf8" }).stdout ?? "");
  const repository = String(baseline?.repository ?? remote ?? "").toLowerCase();
  if (!repository) {
    console.error(`${GATE}: cannot tell which repository this is (no GitHub remote, no "repository" in .governance/${GATE}.json); add it to the baseline`);
    return 1;
  }
  const ignore = baseline?.ignore ?? [];
  const files = {};
  for (const file of trackedFiles(root).filter((f) => scanned(f, ignore))) {
    const full = join(root, file);
    if (existsSync(full) && statSync(full).isFile() && statSync(full).size <= 2 * 1024 * 1024) files[file] = readFileSync(full, "utf8");
  }
  const { findings, examples } = boundaryFindings({ repository, files });
  return finish({
    gate: GATE,
    root,
    findings,
    argv,
    scanned: `${Object.keys(files).length} files of ${repository} (${classOf(repository)})`,
    describe: (key, value, before) => `${key}: ${value}${before === undefined ? "" : ` (baseline ${before})`}; ${examples[key] ?? ""}`,
    hint: "Keep kernel privileges in the kernel (GOVERNANCE GL11, ADR 0003): a provider or product obtains access through NewAPI's /v1/access with an API key, at public addresses; no svc_ identity, no in-network kernel address, no shared platform deploy secret, no NewAPI administrator token, no aud netbird.",
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(main(process.argv.slice(2)));
