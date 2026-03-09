import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";

const args = process.argv.slice(2).filter((arg) => arg !== "--");
const cwd = process.cwd();

const getArgValue = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};

const runGitLines = (command) => {
  return execSync(command, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
};

const runGitOutput = (command) => {
  return execSync(command, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
};

const safeGitList = (primaryCommand, fallbackCommands = []) => {
  try {
    return runGitLines(primaryCommand);
  } catch {
    for (const command of fallbackCommands) {
      try {
        return runGitLines(command);
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

  return files
    .filter((file) => /^Apps\/[^/]+\/docker-compose\.ya?ml$/u.test(file))
    .filter((file) => fs.existsSync(path.join(cwd, file)));
};

const loadCredentialsPolicy = () => {
  const dedicatedPolicyPath = path.join(cwd, "policy", "credential-policy.json");
  if (fs.existsSync(dedicatedPolicyPath)) {
    return JSON.parse(fs.readFileSync(dedicatedPolicyPath, "utf8"));
  }

  const legacyPolicyPath = path.join(cwd, "policy", "app-default-mappings.json");
  if (!fs.existsSync(legacyPolicyPath)) {
    console.error(
      `❌ Credential policy not found. Expected ${dedicatedPolicyPath} or ${legacyPolicyPath}`
    );
    process.exit(1);
  }

  const legacyPolicy = JSON.parse(fs.readFileSync(legacyPolicyPath, "utf8"));
  if (legacyPolicy?.credentials && typeof legacyPolicy.credentials === "object") {
    return legacyPolicy.credentials;
  }

  const referencedCredentialPath = legacyPolicy?.policyFiles?.credentials;
  if (typeof referencedCredentialPath === "string") {
    const resolvedPath = path.resolve(cwd, referencedCredentialPath);
    if (fs.existsSync(resolvedPath)) {
      return JSON.parse(fs.readFileSync(resolvedPath, "utf8"));
    }
  }

  console.error(
    `❌ Credential policy not found in legacy index. Add policy/credential-policy.json or populate credentials in ${legacyPolicyPath}.`
  );
  process.exit(1);
};

const credentialsPolicy = loadCredentialsPolicy();
const sensitivePatterns = (credentialsPolicy.sensitiveKeyPatterns ?? []).map((value) =>
  String(value).toUpperCase()
);
const weakDefaults = (credentialsPolicy.disallowedWeakDefaults ?? []).map((value) =>
  String(value).toLowerCase()
);
const allowedPlaceholderValues = new Set(
  (credentialsPolicy.allowedPlaceholderValues ?? []).map((value) => String(value))
);
const allowPlaceholders = Boolean(credentialsPolicy.allowPlaceholders);

const globalExceptions = new Set(
  ((credentialsPolicy.exceptions?.global ?? []) || []).map((value) => String(value).toUpperCase())
);
const byAppExceptionsRaw = credentialsPolicy.exceptions?.byApp ?? {};

const normalizeString = (value) => {
  if (value === null || value === undefined) return "";
  return String(value).trim();
};

const isSensitiveKey = (key) => {
  const upper = key.toUpperCase();
  return sensitivePatterns.some((pattern) => {
    if (pattern === "PASS") {
      return /(^|_)(PASS|PASSWORD|PASSPHRASE)(_|$)/u.test(upper);
    }
    if (pattern === "KEY") {
      return /(^|_)(KEY|API_KEY|PRIVATE_KEY|SECRET_KEY|ACCESS_KEY)(_|$)/u.test(upper);
    }
    return upper.includes(pattern);
  });
};

const isPlaceholderValue = (value) => {
  if (!allowPlaceholders) return false;
  if (allowedPlaceholderValues.has(value)) return true;
  if (/^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/u.test(value)) return true;
  if (/^\$\{\{[^}]+\}\}$/u.test(value)) return true;
  return false;
};

const appHasExceptionForKey = (appId, key) => {
  const appException = byAppExceptionsRaw?.[appId];
  if (!appException) return false;
  if (Array.isArray(appException)) {
    const entries = appException.map((value) => String(value).toUpperCase());
    return entries.includes(key.toUpperCase());
  }
  return false;
};

const collectEnvironmentEntries = (environment) => {
  const entries = [];
  if (Array.isArray(environment)) {
    for (const item of environment) {
      if (typeof item === "string") {
        const separatorIndex = item.indexOf("=");
        if (separatorIndex === -1) {
          const key = item.trim();
          if (key) entries.push({ key, value: "" });
          continue;
        }
        const key = item.slice(0, separatorIndex).trim();
        const value = item.slice(separatorIndex + 1);
        if (key) entries.push({ key, value });
        continue;
      }
      if (item && typeof item === "object") {
        for (const [key, value] of Object.entries(item)) {
          entries.push({ key, value });
        }
      }
    }
    return entries;
  }

  if (environment && typeof environment === "object") {
    for (const [key, value] of Object.entries(environment)) {
      entries.push({ key, value });
    }
  }
  return entries;
};

const maskValue = (value) => {
  if (!value) return "<empty>";
  if (value.length <= 4) return "***";
  return `${value.slice(0, 2)}***${value.slice(-2)}`;
};

const parseCompose = (content) => {
  try {
    const parsed = yaml.load(content);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
};

const loadComposeFromRef = (ref, file) => {
  try {
    const content = runGitOutput(`git show ${ref}:${file}`);
    return parseCompose(content);
  } catch {
    return null;
  }
};

const collectIssuesFromCompose = (file, compose) => {
  const issues = [];
  if (!compose || typeof compose !== "object") return issues;

  const appIdMatch = file.match(/^Apps\/([^/]+)\//u);
  const appId = appIdMatch?.[1] ?? "unknown-app";
  const services = compose?.services;
  if (!services || typeof services !== "object") return issues;

  for (const [serviceName, serviceDefinition] of Object.entries(services)) {
    if (!serviceDefinition || typeof serviceDefinition !== "object") continue;

    const environmentEntries = collectEnvironmentEntries(serviceDefinition.environment);
    for (const { key, value } of environmentEntries) {
      const normalizedKey = normalizeString(key);
      if (!normalizedKey) continue;
      if (!isSensitiveKey(normalizedKey)) continue;

      const upperKey = normalizedKey.toUpperCase();
      if (globalExceptions.has(upperKey) || appHasExceptionForKey(appId, upperKey)) continue;

      const normalizedValue = normalizeString(value);
      if (isPlaceholderValue(normalizedValue)) continue;

      const lowerValue = normalizedValue.toLowerCase();
      const weakMatch = weakDefaults.find(
        (weakValue) => weakValue && lowerValue.includes(weakValue)
      );

      if (weakMatch) {
        issues.push({
          file,
          appId,
          serviceName,
          key: normalizedKey,
          value: normalizedValue,
          reason: `disallowed weak default "${weakMatch}"`,
        });
        continue;
      }

      issues.push({
        file,
        appId,
        serviceName,
        key: normalizedKey,
        value: normalizedValue,
        reason: "non-placeholder sensitive value (keep real credentials outside git)",
      });
    }
  }

  return issues;
};

const issueSignature = (issue) =>
  [
    issue.file,
    issue.appId,
    issue.serviceName,
    issue.key,
    issue.value,
    issue.reason,
  ].join("|");

const files = listCandidateFiles();
if (files.length === 0) {
  console.log("✅ Credential policy check skipped (no target docker-compose files in scope).");
  process.exit(0);
}

const baseSha = getArgValue("--base-sha");
const headSha = getArgValue("--head-sha");
const compareAgainstBase = Boolean(baseSha && headSha);

const issues = [];

for (const file of files) {
  const workingPath = path.join(cwd, file);
  const headCompose =
    compareAgainstBase && headSha
      ? loadComposeFromRef(headSha, file) ?? parseCompose(fs.readFileSync(workingPath, "utf8"))
      : parseCompose(fs.readFileSync(workingPath, "utf8"));

  if (!headCompose) continue;
  const headIssues = collectIssuesFromCompose(file, headCompose);

  if (!compareAgainstBase) {
    issues.push(...headIssues);
    continue;
  }

  const baseCompose = loadComposeFromRef(baseSha, file);
  if (!baseCompose) {
    issues.push(...headIssues);
    continue;
  }

  const baseSignatures = new Set(
    collectIssuesFromCompose(file, baseCompose).map((issue) => issueSignature(issue))
  );

  for (const issue of headIssues) {
    if (!baseSignatures.has(issueSignature(issue))) {
      issues.push(issue);
    }
  }
}

if (issues.length > 0) {
  console.error(`❌ Credential policy violations detected (${issues.length})`);
  for (const issue of issues) {
    console.error(
      `- ${issue.file} [app=${issue.appId}, service=${issue.serviceName}] key=${issue.key} value=${maskValue(
        issue.value
      )} reason=${issue.reason}`
    );
  }
  process.exit(1);
}

if (compareAgainstBase) {
  console.log(
    `✅ Credential policy check passed (${files.length} file(s) checked, no newly introduced violations).`
  );
} else {
  console.log(`✅ Credential policy check passed (${files.length} file(s) checked).`);
}

