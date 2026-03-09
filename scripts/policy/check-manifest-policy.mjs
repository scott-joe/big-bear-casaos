import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";

const cwd = process.cwd();
const appsDir = path.join(cwd, "Apps");
const storagePolicyPath = path.join(cwd, "policy", "storage-policy.json");
const portPolicyPath = path.join(cwd, "policy", "port-policy.json");

const readJson = (filePath) => {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing required policy file: ${filePath}`);
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
};

const normalizePortEntryString = (value) => String(value).trim().replace(/^['"]|['"]$/gu, "");

const toPortNumber = (value) => {
  if (value === null || value === undefined) return null;
  const asString = String(value).trim();
  if (!/^\d+$/u.test(asString)) return null;
  const parsed = Number(asString);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) return null;
  return parsed;
};

const parsePortString = (value) => {
  const raw = normalizePortEntryString(value);
  let main = raw;
  let protocol = "tcp";
  const protocolMatch = main.match(/\/(tcp|udp|sctp)$/iu);
  if (protocolMatch) {
    protocol = protocolMatch[1].toLowerCase();
    main = main.slice(0, -protocolMatch[0].length);
  }

  if (main.includes("-")) {
    return {
      raw,
      protocol,
      isRange: true,
      published: null,
      target: null,
      parsable: true,
    };
  }

  const parts = main.split(":");
  if (parts.length === 1) {
    return {
      raw,
      protocol,
      isRange: false,
      published: null,
      target: toPortNumber(parts[0]),
      parsable: toPortNumber(parts[0]) !== null,
    };
  }

  if (parts.length === 2) {
    const published = toPortNumber(parts[0]);
    const target = toPortNumber(parts[1]);
    return {
      raw,
      protocol,
      isRange: false,
      published,
      target,
      parsable: published !== null && target !== null,
    };
  }

  const published = toPortNumber(parts.at(-2));
  const target = toPortNumber(parts.at(-1));
  return {
    raw,
    protocol,
    isRange: false,
    published,
    target,
    parsable: published !== null && target !== null,
  };
};

const parseVolumeString = (value) => {
  const raw = String(value);
  const parts = raw.split(":");
  if (parts.length < 2) return null;
  const source = parts[0];
  const target = parts[1];
  if (!source || !target) return null;
  return { source, target };
};

const getServiceEntries = (doc) => {
  if (!doc || typeof doc !== "object" || !doc.services || typeof doc.services !== "object") {
    return [];
  }
  return Object.entries(doc.services);
};

const getRangeExceptionSetForApp = (rangePortExceptions, appId) => {
  if (!rangePortExceptions || typeof rangePortExceptions !== "object") return new Set();
  const entries = rangePortExceptions[appId];
  if (!Array.isArray(entries)) return new Set();
  return new Set(entries.map((value) => normalizePortEntryString(value)));
};

const hasPathPrefix = (value, prefix) => {
  if (typeof value !== "string" || typeof prefix !== "string" || !prefix) return false;
  if (value === prefix) return true;
  if (value.startsWith(`${prefix}/`)) return true;
  return value.includes(`${prefix}/`);
};

const findPrimaryHostPort = (doc) => {
  const services = doc?.services;
  if (!services || typeof services !== "object") return null;
  const mainService = String(doc?.["x-casaos"]?.main || "");

  const order = [];
  if (mainService && Object.prototype.hasOwnProperty.call(services, mainService)) order.push(mainService);
  for (const serviceName of Object.keys(services)) {
    if (!order.includes(serviceName)) order.push(serviceName);
  }

  for (const serviceName of order) {
    const service = services[serviceName];
    if (!Array.isArray(service?.ports)) continue;
    for (const entry of service.ports) {
      if (typeof entry === "string") {
        const parsed = parsePortString(entry);
        if (parsed.parsable && !parsed.isRange && parsed.published !== null) return parsed.published;
        continue;
      }
      if (entry && typeof entry === "object") {
        const published = toPortNumber(entry.published ?? entry.host_port ?? entry.hostPort);
        if (published !== null) return published;
      }
    }
  }
  return null;
};

const storagePolicy = readJson(storagePolicyPath);
const portPolicy = readJson(portPolicyPath);

if (!fs.existsSync(appsDir)) {
  throw new Error(`Apps directory not found: ${appsDir}`);
}

const hostNetworkApps = new Set(
  Array.isArray(portPolicy?.hostNetworkApps) ? portPolicy.hostNetworkApps : []
);
const rangePortExceptions = portPolicy?.rangePortExceptions ?? {};
const allowDuplicatePortMapForApps = new Set(
  Array.isArray(portPolicy?.allowDuplicatePortMapForApps)
    ? portPolicy.allowDuplicatePortMapForApps
    : []
);

const issues = [];
const hostPortUsage = new Map();
const portMapUsage = new Map();
let appsScanned = 0;

const composeFiles = fs
  .readdirSync(appsDir, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => ({
    appId: entry.name,
    filePath: path.join(appsDir, entry.name, "docker-compose.yml"),
  }))
  .filter((entry) => fs.existsSync(entry.filePath))
  .sort((a, b) => a.appId.localeCompare(b.appId));

for (const { appId, filePath } of composeFiles) {
  appsScanned += 1;
  const relativeFile = path.relative(cwd, filePath);
  const content = fs.readFileSync(filePath, "utf8");
  const doc = yaml.load(content);
  if (!doc || typeof doc !== "object") {
    issues.push({
      code: "invalid-compose-yaml",
      file: relativeFile,
      appId,
      detail: "Compose document is not a valid object.",
    });
    continue;
  }

  const isHostNetwork =
    hostNetworkApps.has(appId) ||
    getServiceEntries(doc).some(([, service]) => service?.network_mode === "host");

  const registerPathViolation = (fieldPath, value) => {
    const asString = String(value);
    if (asString.includes("/DATA/AppData/")) {
      issues.push({
        code: "legacy-appdata-path",
        file: relativeFile,
        appId,
        detail: `${fieldPath} uses legacy /DATA/AppData path: ${asString}`,
      });
    }

    const dockerRoots = Array.isArray(storagePolicy?.dockerRoots) ? storagePolicy.dockerRoots : [];
    for (const mapping of dockerRoots) {
      const legacyRoot = String(mapping?.match || "");
      if (!legacyRoot) continue;
      if (!hasPathPrefix(asString, legacyRoot)) continue;
      issues.push({
        code: "visible-docker-root-path",
        file: relativeFile,
        appId,
        detail: `${fieldPath} uses non-hidden docker root path: ${asString}`,
      });
    }
  };

  for (const [serviceName, service] of getServiceEntries(doc)) {
    if (Array.isArray(service?.volumes)) {
      service.volumes.forEach((volumeEntry, index) => {
        if (typeof volumeEntry === "string") {
          const parsed = parseVolumeString(volumeEntry);
          if (!parsed) return;
          if (parsed.source.startsWith("/")) {
            registerPathViolation(`services.${serviceName}.volumes[${index}]`, parsed.source);
          }
          return;
        }

        if (!volumeEntry || typeof volumeEntry !== "object") return;
        const source =
          volumeEntry.source ?? volumeEntry.src ?? volumeEntry.host ?? volumeEntry.bind?.source;
        if (typeof source === "string" && source.startsWith("/")) {
          registerPathViolation(`services.${serviceName}.volumes[${index}]`, source);
        }
      });
    }

    if (Array.isArray(service?.environment)) {
      service.environment.forEach((envEntry, index) => {
        if (typeof envEntry !== "string") return;
        const separatorIndex = envEntry.indexOf("=");
        if (separatorIndex === -1) return;
        const value = envEntry.slice(separatorIndex + 1);
        if (!value.startsWith("/")) return;
        registerPathViolation(`services.${serviceName}.environment[${index}]`, value);
      });
    } else if (service?.environment && typeof service.environment === "object") {
      for (const [envKey, envValue] of Object.entries(service.environment)) {
        if (typeof envValue !== "string" || !envValue.startsWith("/")) continue;
        registerPathViolation(`services.${serviceName}.environment.${envKey}`, envValue);
      }
    }

    if (Array.isArray(service?.ports)) {
      const appRangeExceptions = getRangeExceptionSetForApp(rangePortExceptions, appId);
      service.ports.forEach((portEntry, index) => {
        if (typeof portEntry === "string") {
          const parsed = parsePortString(portEntry);
          if (parsed.isRange) {
            if (!appRangeExceptions.has(parsed.raw)) {
              issues.push({
                code: "unmanaged-port-range",
                file: relativeFile,
                appId,
                detail: `services.${serviceName}.ports[${index}] uses unmanaged range mapping: ${parsed.raw}`,
              });
            }
            return;
          }

          if (!parsed.parsable) {
            issues.push({
              code: "unparseable-port-mapping",
              file: relativeFile,
              appId,
              detail: `services.${serviceName}.ports[${index}] is not parsable: ${normalizePortEntryString(portEntry)}`,
            });
            return;
          }

          if (parsed.published !== null) {
            if (!hostPortUsage.has(parsed.published)) hostPortUsage.set(parsed.published, []);
            hostPortUsage.get(parsed.published).push({
              file: relativeFile,
              appId,
              service: serviceName,
              index,
            });
          }
          return;
        }

        if (!portEntry || typeof portEntry !== "object") return;
        const published = toPortNumber(portEntry.published ?? portEntry.host_port ?? portEntry.hostPort);
        const target = toPortNumber(portEntry.target ?? portEntry.container_port ?? portEntry.containerPort);
        if (published === null || target === null) {
          issues.push({
            code: "unparseable-port-object",
            file: relativeFile,
            appId,
            detail: `services.${serviceName}.ports[${index}] object mapping is missing numeric published/target`,
          });
          return;
        }
        if (!hostPortUsage.has(published)) hostPortUsage.set(published, []);
        hostPortUsage.get(published).push({
          file: relativeFile,
          appId,
          service: serviceName,
          index,
        });
      });
    }
  }

  const primaryHostPort = findPrimaryHostPort(doc);
  const rawPortMap = doc?.["x-casaos"]?.port_map;
  const portMapNumber = toPortNumber(rawPortMap);
  if (primaryHostPort !== null) {
    if (portMapNumber === null) {
      issues.push({
        code: "missing-or-invalid-port-map",
        file: relativeFile,
        appId,
        detail: `x-casaos.port_map is missing/invalid; expected ${primaryHostPort}`,
      });
    } else if (portMapNumber !== primaryHostPort) {
      issues.push({
        code: "port-map-drift",
        file: relativeFile,
        appId,
        detail: `x-casaos.port_map=${portMapNumber} does not match primary host port ${primaryHostPort}`,
      });
    }
  }

  if (
    toPortNumber(rawPortMap) !== null &&
    !(Boolean(portPolicy?.ignoreHostNetworkForPortMapUniqueness) && isHostNetwork)
  ) {
    if (!portMapUsage.has(portMapNumber)) portMapUsage.set(portMapNumber, []);
    portMapUsage.get(portMapNumber).push({ appId, file: relativeFile, isHostNetwork });
  }
}

if (portPolicy?.enforceUniqueHostPorts !== false) {
  for (const [hostPort, holders] of hostPortUsage.entries()) {
    if (holders.length <= 1) continue;
    issues.push({
      code: "duplicate-host-port",
      file: holders.map((holder) => holder.file).join(", "),
      appId: holders.map((holder) => holder.appId).join(", "),
      detail: `Host port ${hostPort} is used by ${holders.length} mappings`,
    });
  }
}

if (Boolean(portPolicy?.enforceUniquePortMap)) {
  for (const [portMap, holders] of portMapUsage.entries()) {
    if (holders.length <= 1) continue;
    const disallowedHolders = holders.filter((holder) => !allowDuplicatePortMapForApps.has(holder.appId));
    if (disallowedHolders.length <= 1) continue;
    issues.push({
      code: "duplicate-port-map",
      file: disallowedHolders.map((holder) => holder.file).join(", "),
      appId: disallowedHolders.map((holder) => holder.appId).join(", "),
      detail: `x-casaos.port_map=${portMap} is duplicated across ${disallowedHolders.length} apps`,
    });
  }
}

if (issues.length > 0) {
  console.error(`❌ Manifest policy check failed (${issues.length} issue(s))`);
  for (const issue of issues) {
    console.error(`- [${issue.code}] ${issue.file} [app=${issue.appId}] ${issue.detail}`);
  }
  process.exit(1);
}

console.log(`✅ Manifest policy check passed (${appsScanned} app compose file(s) checked).`);

