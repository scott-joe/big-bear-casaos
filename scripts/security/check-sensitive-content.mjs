import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const cwd = process.cwd();

const getArgValue = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};

const runGit = (command) => {
  return execSync(command, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
};

const safeGitList = (primaryCommand, fallbackCommands = []) => {
  try {
    return runGit(primaryCommand);
  } catch {
    for (const command of fallbackCommands) {
      try {
        return runGit(command);
      } catch {
        continue;
      }
    }
    return [];
  }
};

const listCandidateFiles = () => {
  const staged = args.includes("--staged");
  const all = args.includes("--all");
  const baseSha = getArgValue("--base-sha");
  const headSha = getArgValue("--head-sha");

  let files = [];

  if (staged) {
    files = safeGitList("git diff --cached --name-only --diff-filter=ACMR");
  } else if (baseSha && headSha) {
    files = safeGitList(
      `git diff --name-only --diff-filter=ACMR ${baseSha} ${headSha}`,
      ["git diff --name-only --diff-filter=ACMR HEAD~1 HEAD"]
    );
  } else if (all) {
    files = safeGitList("git ls-files");
  } else {
    files = safeGitList("git ls-files");
  }

  const ignoredPrefixes = ["node_modules/", ".git/", "converted/"];
  const ignoredFiles = new Set(["pnpm-lock.yaml"]);

  return files
    .filter((file) => !ignoredFiles.has(file))
    .filter((file) => !ignoredPrefixes.some((prefix) => file.startsWith(prefix)))
    .filter((file) => fs.existsSync(path.join(cwd, file)));
};

const textFileFromPath = (absolutePath) => {
  const stat = fs.statSync(absolutePath);
  if (stat.size > 1024 * 1024) return null;

  const content = fs.readFileSync(absolutePath);
  if (content.includes(0)) return null;
  return content.toString("utf8");
};

const patterns = [
  { id: "private-key", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/u },
  { id: "github-token", regex: /\bghp_[A-Za-z0-9]{36}\b/u },
  { id: "github-fine-grained-pat", regex: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/u },
  { id: "gitlab-token", regex: /\bglpat-[A-Za-z0-9\-_]{20,}\b/u },
  { id: "aws-access-key-id", regex: /\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b/u },
  { id: "slack-token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/u },
  { id: "openai-key", regex: /\bsk-[A-Za-z0-9]{20,}\b/u },
  { id: "google-api-key", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/u },
  { id: "npm-token", regex: /\bnpm_[A-Za-z0-9]{36}\b/u },
  { id: "jwt-like-token", regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/u },
];

const files = listCandidateFiles();
if (files.length === 0) {
  console.log("✅ Sensitive-content check skipped (no files in scope).");
  process.exit(0);
}

const findings = [];

for (const file of files) {
  const absolutePath = path.join(cwd, file);
  let content;
  try {
    content = textFileFromPath(absolutePath);
  } catch {
    continue;
  }

  if (!content) continue;
  const lines = content.split("\n");

  lines.forEach((line, index) => {
    for (const pattern of patterns) {
      const match = line.match(pattern.regex);
      if (!match) continue;

      findings.push({
        file,
        lineNumber: index + 1,
        type: pattern.id,
        match: match[0],
      });
    }
  });
}

if (findings.length > 0) {
  console.error(`❌ Sensitive content findings detected (${findings.length})`);
  findings.forEach((finding) => {
    const masked =
      finding.match.length <= 6
        ? "***"
        : `${finding.match.slice(0, 3)}***${finding.match.slice(-3)}`;
    console.error(`- ${finding.file}:${finding.lineNumber} [${finding.type}] ${masked}`);
  });
  process.exit(1);
}

console.log(`✅ Sensitive-content check passed (${files.length} file(s) scanned).`);
