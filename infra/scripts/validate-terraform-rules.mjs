#!/usr/bin/env node
/**
 * Vektor81 Terraform & 2026 Cloudflare DLP Rules Validator (Pure Node ESM, Zero External Deps)
 *
 * Scans every .tf file in infra/terraform/ and enforces:
 *   1. Balanced HCL braces { }, brackets [ ], parens ( ), and string quotes / heredocs.
 *   2. Every Cloudflare DLP regex pattern string contains ZERO unescaped '*' or '+' quantifiers.
 *   3. Total custom DLP regex entries <= 25 per account.
 *   4. Every Custom Wordlist (CWL) contains <= 200 words (total <= 1,000) and ZERO Panamanian
 *      cedula / RUC / NT / passport PII patterns.
 */

import { readdir, readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const MAX_REGEX_ENTRIES_PER_ACCOUNT = 25;
const MAX_WORDS_PER_CWL = 200;
const MAX_TOTAL_CWL_WORDS = 1000;

const PANAMA_PII_FORBIDDEN_IN_CWL = [
  { name: "PA Standard/AV/PI Cedula", pattern: /\b(?:1[0-3]|[1-9])(?:AV|PI)?-\d{1,4}-\d{1,6}\b/i },
  { name: "PA Special PE/E/N Cedula", pattern: /\b(?:PE|E|N)-\d{1,4}-\d{1,6}\b/i },
  { name: "PA NT Foreigner ID", pattern: /\b(?:1[0-3]|[1-9])-NT-\d{1,4}-\d{1,6}\b/i },
  { name: "Numeric Dash ID / Corporate RUC", pattern: /\b\d{1,7}-\d{1,6}-\d{1,6}\b/ },
  { name: "PA Passport APAP", pattern: /\b[A-Z]{2}\d{7}\b/ },
];

export async function collectTfFiles(rootDir) {
  const results = [];
  async function walk(dir) {
    const entries = await readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.name === ".terraform" || entry.name === "node_modules") continue;
      const fullPath = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(".tf")) {
        results.push(fullPath);
      }
    }
  }
  await walk(rootDir);
  return results;
}

export function unescapeHclString(raw) {
  let out = "";
  for (let i = 0; i < raw.length; i += 1) {
    if (raw[i] !== "\\") {
      out += raw[i];
      continue;
    }
    const next = raw[i + 1];
    if (next === undefined) {
      out += "\\";
      break;
    }
    i += 1;
    switch (next) {
      case "\\":
        out += "\\";
        break;
      case '"':
        out += '"';
        break;
      case "n":
        out += "\n";
        break;
      case "r":
        out += "\r";
        break;
      case "t":
        out += "\t";
        break;
      default:
        out += `\\${next}`;
        break;
    }
  }
  return out;
}

/**
 * Validates balanced HCL braces { }, brackets [ ], parens ( ), comments, quotes,
 * ${...} template interpolations, and heredocs (<<EOF / <<-EOF).
 */
export function validateHclBalance(source, fileLabel = "<input>") {
  const errors = [];
  const stack = [];
  const len = source.length;
  let i = 0;
  let line = 1;

  function advanceLine(ch) {
    if (ch === "\n") line += 1;
  }

  function scanQuotedString(startLine) {
    // Assumes opening '"' already consumed
    while (i < len) {
      const ch = source[i];
      if (ch === "\\") {
        i += 2;
        if (i <= len && source[i - 1] === "\n") line += 1;
        continue;
      }
      if (ch === "$" && source[i + 1] === "{") {
        const interpLine = line;
        i += 2;
        stack.push({ open: "${", expected: "}", line: interpLine });
        scanCodeUntilClosingBrace();
        continue;
      }
      if (ch === '"') {
        i += 1;
        return;
      }
      advanceLine(ch);
      i += 1;
    }
    errors.push(`${fileLabel}:${startLine}: Unterminated double-quoted string literal`);
  }

  function scanHeredoc(marker, startLine) {
    // Advance past rest of opening line
    while (i < len && source[i] !== "\n") i += 1;
    if (i < len) {
      line += 1;
      i += 1;
    }

    while (i < len) {
      const lineStart = i;
      let lineEnd = source.indexOf("\n", lineStart);
      if (lineEnd === -1) lineEnd = len;
      const rawLine = source.slice(lineStart, lineEnd).replace(/\r$/, "");
      if (rawLine.trim() === marker) {
        i = lineEnd < len ? lineEnd + 1 : len;
        if (lineEnd < len) line += 1;
        return;
      }
      // Scan line for ${...} interpolations so quotes/braces inside heredoc interpolations balance
      while (i < lineEnd) {
        if (source[i] === "$" && source[i + 1] === "{") {
          const interpLine = line;
          i += 2;
          stack.push({ open: "${", expected: "}", line: interpLine });
          scanCodeUntilClosingBrace();
          lineEnd = source.indexOf("\n", i);
          if (lineEnd === -1) lineEnd = len;
          continue;
        }
        i += 1;
      }
      if (lineEnd < len) {
        line += 1;
        i = lineEnd + 1;
      }
    }
    errors.push(`${fileLabel}:${startLine}: Unterminated heredoc (expected closing "${marker}")`);
  }

  function scanCodeUntilClosingBrace() {
    while (i < len) {
      const ch = source[i];
      if (ch === "#" || (ch === "/" && source[i + 1] === "/")) {
        while (i < len && source[i] !== "\n") i += 1;
        continue;
      }
      if (ch === "/" && source[i + 1] === "*") {
        const commentStart = line;
        i += 2;
        let closed = false;
        while (i < len) {
          if (source[i] === "*" && source[i + 1] === "/") {
            i += 2;
            closed = true;
            break;
          }
          advanceLine(source[i]);
          i += 1;
        }
        if (!closed) {
          errors.push(`${fileLabel}:${commentStart}: Unterminated block comment /* ... */`);
        }
        continue;
      }
      if (ch === "<" && source[i + 1] === "<") {
        const rest = source.slice(i);
        const m = rest.match(/^<<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?(?:\n|$)/);
        if (m) {
          const startLine = line;
          i += m[0].indexOf(m[1]) + m[1].length;
          scanHeredoc(m[1], startLine);
          continue;
        }
      }
      if (ch === '"') {
        const strLine = line;
        i += 1;
        scanQuotedString(strLine);
        continue;
      }
      if (ch === "{") {
        stack.push({ open: "{", expected: "}", line });
        i += 1;
        continue;
      }
      if (ch === "[") {
        stack.push({ open: "[", expected: "]", line });
        i += 1;
        continue;
      }
      if (ch === "(") {
        stack.push({ open: "(", expected: ")", line });
        i += 1;
        continue;
      }
      if (ch === "}" || ch === "]" || ch === ")") {
        const top = stack.pop();
        if (!top) {
          errors.push(`${fileLabel}:${line}: Unexpected closing '${ch}' with no matching opener`);
          i += 1;
          continue;
        }
        if (top.expected !== ch) {
          errors.push(
            `${fileLabel}:${line}: Mismatched '${ch}' (expected '${top.expected}' for '${top.open}' opened on line ${top.line})`
          );
          i += 1;
          continue;
        }
        i += 1;
        if (top.open === "${") {
          return;
        }
        continue;
      }
      advanceLine(ch);
      i += 1;
    }
  }

  scanCodeUntilClosingBrace();

  while (stack.length > 0) {
    const unclosed = stack.pop();
    errors.push(
      `${fileLabel}:${unclosed.line}: Unclosed '${unclosed.open}' (missing '${unclosed.expected}')`
    );
  }

  return errors;
}

/**
 * Strips HCL comments (#, //, /* ... *\/) while preserving string literals intact.
 */
function stripHclComments(source) {
  let out = "";
  let i = 0;
  const len = source.length;
  while (i < len) {
    const ch = source[i];
    if (ch === '"') {
      out += ch;
      i += 1;
      while (i < len) {
        const sc = source[i];
        out += sc;
        i += 1;
        if (sc === "\\" && i < len) {
          out += source[i];
          i += 1;
        } else if (sc === '"') {
          break;
        }
      }
      continue;
    }
    if (ch === "#" || (ch === "/" && source[i + 1] === "/")) {
      while (i < len && source[i] !== "\n") i += 1;
      continue;
    }
    if (ch === "/" && source[i + 1] === "*") {
      i += 2;
      while (i < len && !(source[i] === "*" && source[i + 1] === "/")) {
        if (source[i] === "\n") out += "\n";
        i += 1;
      }
      i += 2;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

function findMatchingBrace(text, openIndex) {
  let depth = 0;
  let i = openIndex;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      i += 1;
      while (i < text.length) {
        if (text[i] === "\\") {
          i += 2;
          continue;
        }
        if (text[i] === '"') {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
    i += 1;
  }
  return -1;
}

function lineNumberAt(text, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < text.length; i += 1) {
    if (text[i] === "\n") line += 1;
  }
  return line;
}

/**
 * Checks a Rust DLP regex string for unescaped '*' or '+' quantifiers and compiles it.
 */
export function validateRustRegexNoUnboundedQuantifiers(regexStr) {
  const issues = [];
  let inCharClass = false;
  let escaped = false;

  for (let i = 0; i < regexStr.length; i += 1) {
    const ch = regexStr[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === "[" && !inCharClass) {
      inCharClass = true;
      continue;
    }
    if (ch === "]" && inCharClass) {
      inCharClass = false;
      continue;
    }
    if (!inCharClass && (ch === "*" || ch === "+")) {
      issues.push(`unescaped '${ch}' quantifier at index ${i}`);
    }
  }

  try {
    // Sanity compile check (JS RegExp accepts standard Rust subset used here)
    new RegExp(regexStr);
  } catch (err) {
    issues.push(`invalid regex syntax: ${err.message}`);
  }

  return issues;
}

export function extractDlpRegexPatterns(cleanSource, fileLabel) {
  const patterns = [];
  const regexAssignRe = /\bregex\s*=\s*"((?:[^"\\]|\\.)*)"/g;
  let match;
  while ((match = regexAssignRe.exec(cleanSource)) !== null) {
    patterns.push({
      file: fileLabel,
      line: lineNumberAt(cleanSource, match.index),
      raw: match[1],
      regex: unescapeHclString(match[1]),
    });
  }
  return patterns;
}

export function countCustomRegexEntries(cleanSource) {
  // Collect top-level locals maps so for_each = local.<map> counts exact expanded entries
  const localMapKeyCounts = new Map();
  const localsRe = /\blocals\s*\{/g;
  let localsMatch;
  while ((localsMatch = localsRe.exec(cleanSource)) !== null) {
    const openIdx = localsMatch.index + localsMatch[0].length - 1;
    const closeIdx = findMatchingBrace(cleanSource, openIdx);
    if (closeIdx === -1) continue;
    const localsBody = cleanSource.slice(openIdx + 1, closeIdx);
    const mapAssignRe = /\b([A-Za-z0-9_]+)\s*=\s*\{/g;
    let m;
    while ((m = mapAssignRe.exec(localsBody)) !== null) {
      const mOpen = m.index + m[0].length - 1;
      const mClose = findMatchingBrace(localsBody, mOpen);
      if (mClose === -1) continue;
      const mapBody = localsBody.slice(mOpen + 1, mClose);
      // Count top-level object keys that contain regex = "..."
      let keyCount = 0;
      const entryKeyRe = /\b[A-Za-z0-9_]+\s*=\s*\{/g;
      let ek;
      while ((ek = entryKeyRe.exec(mapBody)) !== null) {
        const eOpen = ek.index + ek[0].length - 1;
        const eClose = findMatchingBrace(mapBody, eOpen);
        if (eClose === -1) continue;
        const entryBody = mapBody.slice(eOpen + 1, eClose);
        if (/\bregex\s*=/.test(entryBody)) {
          keyCount += 1;
        }
        entryKeyRe.lastIndex = eClose + 1;
      }
      if (keyCount > 0) {
        localMapKeyCounts.set(m[1], keyCount);
      }
      mapAssignRe.lastIndex = mClose + 1;
    }
    localsRe.lastIndex = closeIdx + 1;
  }

  let regexEntryCount = 0;
  let wordlistEntryCount = 0;

  const resourceRe = /\bresource\s+"cloudflare_zero_trust_dlp_custom_entry"\s+"([A-Za-z0-9_]+)"\s*\{/g;
  let resMatch;
  while ((resMatch = resourceRe.exec(cleanSource)) !== null) {
    const openIdx = resMatch.index + resMatch[0].length - 1;
    const closeIdx = findMatchingBrace(cleanSource, openIdx);
    if (closeIdx === -1) continue;
    const body = cleanSource.slice(openIdx + 1, closeIdx);

    const isWordList = /\btype\s*=\s*"word_list"/.test(body) || /\bword_list\s*=\s*\[/.test(body);
    if (isWordList) {
      wordlistEntryCount += 1;
      continue;
    }

    const forEachLocal = body.match(/\bfor_each\s*=\s*local\.([A-Za-z0-9_]+)/);
    if (forEachLocal && localMapKeyCounts.has(forEachLocal[1])) {
      regexEntryCount += localMapKeyCounts.get(forEachLocal[1]);
    } else if (/\bpattern\s*=/.test(body)) {
      regexEntryCount += 1;
    }
  }

  return { regexEntryCount, wordlistEntryCount };
}

export function extractWordLists(cleanSource, fileLabel) {
  const lists = [];
  const resRe = /\bresource\s+"cloudflare_zero_trust_dlp_custom_entry"\s+"([A-Za-z0-9_]+)"\s*\{/g;
  let resMatch;
  while ((resMatch = resRe.exec(cleanSource)) !== null) {
    const resName = resMatch[1];
    const openIdx = resMatch.index + resMatch[0].length - 1;
    const closeIdx = findMatchingBrace(cleanSource, openIdx);
    if (closeIdx === -1) continue;
    const body = cleanSource.slice(openIdx + 1, closeIdx);
    const wlMatch = /\bword_list\s*=\s*\[([\s\S]*?)\]/.exec(body);
    if (!wlMatch) continue;

    const words = [];
    const strRe = /"((?:[^"\\]|\\.)*)"/g;
    let sm;
    while ((sm = strRe.exec(wlMatch[1])) !== null) {
      words.push(unescapeHclString(sm[1]));
    }
    lists.push({
      file: fileLabel,
      resourceName: resName,
      line: lineNumberAt(cleanSource, resMatch.index),
      words,
    });
  }
  return lists;
}

export function containsPanamaPii(term) {
  for (const check of PANAMA_PII_FORBIDDEN_IN_CWL) {
    if (check.pattern.test(term)) {
      return check.name;
    }
  }
  return null;
}

export async function validateTerraformDirectory(tfRootDir) {
  const tfFiles = await collectTfFiles(tfRootDir);
  if (tfFiles.length === 0) {
    throw new Error(`No .tf files found under ${tfRootDir}`);
  }

  const failures = [];
  const allRegexPatterns = [];
  const allWordLists = [];
  let totalCustomRegexEntries = 0;

  for (const absPath of tfFiles) {
    const relPath = relative(tfRootDir, absPath).replace(/\\/g, "/");
    const rawSource = await readFile(absPath, "utf8");

    // 1. HCL syntax balance (braces, brackets, parens, quotes, heredocs)
    const hclErrors = validateHclBalance(rawSource, relPath);
    failures.push(...hclErrors);

    const cleanSource = stripHclComments(rawSource);

    // 2. Extract and validate DLP regex patterns
    const regexPatterns = extractDlpRegexPatterns(cleanSource, relPath);
    for (const item of regexPatterns) {
      allRegexPatterns.push(item);
      const regexIssues = validateRustRegexNoUnboundedQuantifiers(item.regex);
      for (const issue of regexIssues) {
        failures.push(`${item.file}:${item.line}: DLP regex "${item.regex}" violates Rust constraint (${issue})`);
      }
    }

    // 3. Count custom regex entries
    const counts = countCustomRegexEntries(cleanSource);
    totalCustomRegexEntries += counts.regexEntryCount;

    // 4. Extract Custom Wordlists (CWL)
    const wordLists = extractWordLists(cleanSource, relPath);
    allWordLists.push(...wordLists);
  }

  // Enforce total custom regex entries <= 25 (and >= 1)
  if (totalCustomRegexEntries === 0) {
    failures.push("Expected at least 1 custom DLP regex entry, found 0.");
  }
  if (totalCustomRegexEntries > MAX_REGEX_ENTRIES_PER_ACCOUNT) {
    failures.push(
      `Custom DLP regex entry count (${totalCustomRegexEntries}) exceeds Cloudflare 2026 limit of ${MAX_REGEX_ENTRIES_PER_ACCOUNT} per account.`
    );
  }

  // Enforce CWL limits (<= 200 per list, <= 1,000 total, ZERO Panamanian PII)
  let totalCwlWords = 0;
  for (const wl of allWordLists) {
    totalCwlWords += wl.words.length;
    if (wl.words.length === 0) {
      failures.push(`${wl.file}:${wl.line}: Custom Wordlist "${wl.resourceName}" is empty.`);
    }
    if (wl.words.length > MAX_WORDS_PER_CWL) {
      failures.push(
        `${wl.file}:${wl.line}: Custom Wordlist "${wl.resourceName}" has ${wl.words.length} words (max ${MAX_WORDS_PER_CWL}).`
      );
    }
    for (const term of wl.words) {
      const piiHit = containsPanamaPii(term);
      if (piiHit) {
        failures.push(
          `${wl.file}:${wl.line}: Custom Wordlist "${wl.resourceName}" contains forbidden PII (${piiHit}): "${term}"`
        );
      }
    }
  }

  if (totalCwlWords > MAX_TOTAL_CWL_WORDS) {
    failures.push(
      `Total Custom Wordlist words (${totalCwlWords}) exceeds Cloudflare 2026 limit of ${MAX_TOTAL_CWL_WORDS} per account.`
    );
  }

  return {
    ok: failures.length === 0,
    tfFilesCount: tfFiles.length,
    tfFiles: tfFiles.map((f) => relative(tfRootDir, f).replace(/\\/g, "/")),
    totalCustomRegexEntries,
    regexPatternsChecked: allRegexPatterns.length,
    wordListsChecked: allWordLists.map((w) => ({
      resourceName: w.resourceName,
      file: w.file,
      wordCount: w.words.length,
    })),
    totalCwlWords,
    failures,
  };
}

async function main() {
  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const defaultTfRoot = resolve(scriptDir, "..", "terraform");
  const dirArgIdx = process.argv.indexOf("--dir");
  const tfRoot = dirArgIdx >= 0 && process.argv[dirArgIdx + 1] ? resolve(process.argv[dirArgIdx + 1]) : defaultTfRoot;

  const report = await validateTerraformDirectory(tfRoot);
  console.log(JSON.stringify(report, null, 2));

  if (!report.ok) {
    process.exit(1);
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((err) => {
    console.error(`ERROR: ${err.message}`);
    process.exit(1);
  });
}
