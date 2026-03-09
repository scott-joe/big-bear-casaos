import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";

const args = process.argv.slice(2);
const cwd = process.cwd();

const hasArg = (name) => args.includes(name);

const getArgValue = (name) => {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
};

const writeMode = hasArg("--write");
const dryRun = writeMode ? false : true;
const verbose = hasArg("--verbose");
const reportPathArg = getArgValue("--report");
const appFilterArg = getArgValue("--app");
const appFilter = appFilterArg
  ? new Set(
      appFilterArg
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean)
    )
  : null;

const APPS_DIR = path.join(cwd, "Apps");
const STORAGE_POLICY_PATH = path.join(cwd, "policy", "storage-policy.json");
const PORT_POLICY_PATH = path.join(cwd, "policy", "port-policy.json");

const readJson = (filePath) => {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing required policy file: ${filePath}`);
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
};

const toPortNumber = (value) => {
  if (value === null || value === undefined) return null;
  const asString = String(value).trim();
  if (!/^\d+$/u.test(asString)) return null;
  const parsed = Number(asString);
  if (!Number.isInteger(parsed)) return null;
  if (parsed < 1 || parsed > 65535) return null;
  return parsed;
};

const replacePathPrefix = (value, match, replacement) => {
  if (typeof value !== "string" || typeof match !== "string" || typeof replacement !== "string") {
    return null;
  }
  if (value === match) return replacement;
  if (value.startsWith(`${match}/`)) return `${replacement}${value.slice(match.length)}`;
  return null;
};

const parsePortString = (value) => {
  const raw = String(value).trim().replace(/^['"]|['"]$/gu, "");
  let main = raw;
  let protocol = "tcp";
  const protocolMatch = main.match(/\/(tcp|udp|sctp)$/iu);
  if (protocolMatch) {
    protocol = protocolMatch[1].toLowerCase();
    main = main.slice(0, -protocolMatch[0].length);
  }

  if (main.includes("-")) {
    return {
      kind: "string",
      raw,
      protocol,
      parsable: false,
      hasPublished: false,
      ip: null,
      published: null,
      target: null,
      reason: "port ranges are not supported",
    };
  }

  const parts = main.split(":");
  if (parts.length === 1) {
    const target = toPortNumber(parts[0]);
    return {
      kind: "string",
      raw,
      protocol,
      parsable: target !== null,
      hasPublished: false,
      ip: null,
      published: null,
      target,
      reason: target === null ? "unparseable target port" : undefined,
    };
  }

  if (parts.length === 2) {
    const published = toPortNumber(parts[0]);
    const target = toPortNumber(parts[1]);
    return {
      kind: "string",
      raw,
      protocol,
      parsable: published !== null && target !== null,
      hasPublished: published !== null,
      ip: null,
      published,
      target,
      reason: published === null || target === null ? "unparseable port mapping" : undefined,
    };
  }

  const ip = parts.slice(0, -2).join(":");
  const published = toPortNumber(parts.at(-2));
  const target = toPortNumber(parts.at(-1));
  return {
    kind: "string",
    raw,
    protocol,
    parsable: published !== null && target !== null,
    hasPublished: published !== null,
    ip,
    published,
    target,
    reason: published === null || target === null ? "unparseable port mapping" : undefined,
  };
};

const formatPortString = (parsed, published) => {
  const protocolSuffix = parsed.protocol && parsed.protocol !== "tcp" ? `/${parsed.protocol}` : "";
  const targetPart = parsed.target !== null ? String(parsed.target) : "";
  if (!published) {
    return `${targetPart}${protocolSuffix}`;
  }
  const base = parsed.ip
    ? `${parsed.ip}:${String(published)}:${targetPart}`
    : `${String(published)}:${targetPart}`;
  return `${base}${protocolSuffix}`;
};

const parseVolumeString = (value) => {
  const raw = String(value);
  const parts = raw.split(":");
  if (parts.length < 2) return null;
  const source = parts[0];
  const target = parts[1];
  if (!source || !target) return null;
  const mode = parts.length > 2 ? parts.slice(2).join(":") : null;
  return {
    source,
    target,
    mode,
  };
};

const formatVolumeString = (parsed) => {
  if (!parsed.mode) return `${parsed.source}:${parsed.target}`;
  return `${parsed.source}:${parsed.target}:${parsed.mode}`;
};

const isSystemMountPath = (sourcePath, prefixes) => {
  if (!Array.isArray(prefixes)) return false;
  return prefixes.some((prefix) => {
    if (typeof prefix !== "string" || !prefix) return false;
    if (sourcePath === prefix) return true;
    if (prefix.endsWith("/")) {
      return sourcePath.startsWith(prefix) || sourcePath === prefix.slice(0, -1);
    }
    return sourcePath.startsWith(`${prefix}/`);
  });
};

const detectLibraryTarget = ({ sourcePath, containerPath, storagePolicy }) => {
  const libraryPolicy = storagePolicy?.contentLibrary;
  if (!libraryPolicy?.enabled) return null;

  const normalizePath = (value) => String(value).replace(/\/+$/u, "") || "/";
  const normalizedContainer = normalizePath(containerPath || "");
  const exactMappings = libraryPolicy.containerPathMappings ?? {};
  if (Object.prototype.hasOwnProperty.call(exactMappings, normalizedContainer)) {
    return String(exactMappings[normalizedContainer]);
  }

  const legacyRoot = String(storagePolicy?.stateData?.legacyRoot || "");
  const isLegacySource =
    sourcePath.startsWith(legacyRoot) || sourcePath.startsWith("/DATA/AppData/");
  if (!isLegacySource) return null;

  const relativeFromLegacy = sourcePath.startsWith(legacyRoot)
    ? sourcePath.slice(legacyRoot.length)
    : sourcePath.slice("/DATA/AppData/".length);
  const hint = `${relativeFromLegacy} ${containerPath}`.toLowerCase();

  const keywordMappings = Array.isArray(libraryPolicy.keywordMappings)
    ? libraryPolicy.keywordMappings
    : [];
  for (const mapping of keywordMappings) {
    const keyword = String(mapping?.keyword || "").trim().toLowerCase();
    const target = String(mapping?.target || "").trim();
    if (!keyword || !target) continue;
    if (hint.includes(keyword)) return target;
  }
  return null;
};

const rewriteHostPath = ({ appId, sourcePath, containerPath, storagePolicy }) => {
  if (!sourcePath.startsWith("/")) {
    return { updatedPath: sourcePath, classification: "named", changed: false };
  }

  const appOverrideReplacements =
    storagePolicy?.appOverrides?.[appId]?.pathReplacements ?? [];
  for (const replacement of appOverrideReplacements) {
    const updated = replacePathPrefix(
      sourcePath,
      String(replacement?.match || ""),
      String(replacement?.replace || "")
    );
    if (updated && updated !== sourcePath) {
      return { updatedPath: updated, classification: "state-override", changed: true };
    }
  }

  if (isSystemMountPath(sourcePath, storagePolicy?.systemMountPrefixes ?? [])) {
    return { updatedPath: sourcePath, classification: "system", changed: false };
  }

  const dockerRoots = Array.isArray(storagePolicy?.dockerRoots) ? storagePolicy.dockerRoots : [];
  for (const replacement of dockerRoots) {
    const updated = replacePathPrefix(
      sourcePath,
      String(replacement?.match || ""),
      String(replacement?.replace || "")
    );
    if (updated && updated !== sourcePath) {
      return { updatedPath: updated, classification: "docker-root", changed: true };
    }
  }

  const libraryTarget = detectLibraryTarget({ sourcePath, containerPath, storagePolicy });
  if (libraryTarget && libraryTarget !== sourcePath) {
    return { updatedPath: libraryTarget, classification: "library", changed: true };
  }

  const stateLegacyRoot = String(storagePolicy?.stateData?.legacyRoot || "");
  const stateTargetRoot = String(storagePolicy?.stateData?.targetRoot || "");
  if (stateLegacyRoot && stateTargetRoot) {
    const updated = replacePathPrefix(sourcePath, stateLegacyRoot, stateTargetRoot);
    if (updated && updated !== sourcePath) {
      return { updatedPath: updated, classification: "state", changed: true };
    }
  }

  if (sourcePath.startsWith("/DATA/AppData/")) {
    return {
      updatedPath: sourcePath.replace("/DATA/AppData/", "/DATA/.docker/AppData/"),
      classification: "state-fallback",
      changed: true,
    };
  }

  return { updatedPath: sourcePath, classification: "other", changed: false };
};

const rewritePathStringValue = ({ appId, value, storagePolicy }) => {
  if (typeof value !== "string") return { updated: value, changed: false };

  let updated = value;
  const appOverrideReplacements =
    storagePolicy?.appOverrides?.[appId]?.pathReplacements ?? [];

  const replacementRules = [
    ...appOverrideReplacements,
    ...(Array.isArray(storagePolicy?.dockerRoots) ? storagePolicy.dockerRoots : []),
    {
      match: storagePolicy?.stateData?.legacyRoot,
      replace: storagePolicy?.stateData?.targetRoot,
    },
    {
      match: "/DATA/AppData/",
      replace: "/DATA/.docker/AppData/",
    },
  ];

  for (const rule of replacementRules) {
    const match = String(rule?.match || "");
    const replacement = String(rule?.replace || "");
    if (!match || !replacement) continue;

    const asPrefix = replacePathPrefix(updated, match, replacement);
    if (asPrefix && asPrefix !== updated) {
      updated = asPrefix;
      continue;
    }

    if (updated.includes(match)) {
      updated = updated.split(match).join(replacement);
    }
  }

  return { updated, changed: updated !== value };
};

const getServiceEntries = (doc) => {
  if (!doc || typeof doc !== "object" || !doc.services || typeof doc.services !== "object") {
    return [];
  }
  return Object.entries(doc.services);
};

const isAppHostNetwork = ({ appId, doc, portPolicy }) => {
  const hostNetworkApps = new Set(
    Array.isArray(portPolicy?.hostNetworkApps) ? portPolicy.hostNetworkApps : []
  );
  if (hostNetworkApps.has(appId)) return true;
  return getServiceEntries(doc).some(([, service]) => service?.network_mode === "host");
};

const collectCurrentPortRecords = ({ appId, doc }) => {
  const records = [];
  for (const [serviceName, service] of getServiceEntries(doc)) {
    if (!Array.isArray(service?.ports)) continue;
    service.ports.forEach((portEntry, index) => {
      if (typeof portEntry === "string") {
        const parsed = parsePortString(portEntry);
        if (!parsed.parsable || !parsed.hasPublished || parsed.published === null) return;
        records.push({
          appId,
          serviceName,
          index,
          protocol: parsed.protocol || "tcp",
          target: parsed.target,
          published: parsed.published,
        });
        return;
      }

      if (portEntry && typeof portEntry === "object") {
        const published = toPortNumber(
          portEntry.published ?? portEntry.host_port ?? portEntry.hostPort
        );
        const target = toPortNumber(portEntry.target ?? portEntry.container_port ?? portEntry.containerPort);
        if (published === null || target === null) return;
        const protocol = String(portEntry.protocol || "tcp").toLowerCase();
        records.push({
          appId,
          serviceName,
          index,
          protocol,
          target,
          published,
        });
      }
    });
  }
  return records;
};

const buildConflictList = (portRecords) => {
  const usage = new Map();
  for (const record of portRecords) {
    const port = record.published;
    if (!usage.has(port)) usage.set(port, []);
    usage.get(port).push({
      appId: record.appId,
      service: record.serviceName,
      index: record.index,
      protocol: record.protocol,
      containerPort: record.target,
    });
  }

  return [...usage.entries()]
    .filter(([, holders]) => holders.length > 1)
    .sort((a, b) => a[0] - b[0])
    .map(([port, holders]) => ({ port, holders }));
};

const rangesFromPolicy = (portPolicy) => {
  const ranges = Array.isArray(portPolicy?.preferredRanges) ? portPolicy.preferredRanges : [];
  const normalized = ranges
    .map((range) => ({
      start: toPortNumber(range?.start),
      end: toPortNumber(range?.end),
      name: String(range?.name || ""),
    }))
    .filter((range) => range.start !== null && range.end !== null && range.start <= range.end)
    .sort((a, b) => a.start - b.start);
  if (normalized.length > 0) return normalized;
  return [{ name: "default", start: 12000, end: 19999 }];
};

const collectExplicitAssignmentPorts = (explicitAssignments) => {
  const byApp = new Map();
  if (!explicitAssignments || typeof explicitAssignments !== "object") return byApp;

  for (const [appId, assignment] of Object.entries(explicitAssignments)) {
    const ports = new Set();
    if (typeof assignment === "number" || typeof assignment === "string") {
      const parsed = toPortNumber(assignment);
      if (parsed !== null) ports.add(parsed);
    } else if (assignment && typeof assignment === "object") {
      const primary = toPortNumber(assignment.primary);
      if (primary !== null) ports.add(primary);
      if (assignment.byContainerPort && typeof assignment.byContainerPort === "object") {
        Object.values(assignment.byContainerPort).forEach((value) => {
          const parsed = toPortNumber(value);
          if (parsed !== null) ports.add(parsed);
        });
      }
      if (assignment.byService && typeof assignment.byService === "object") {
        Object.values(assignment.byService).forEach((value) => {
          const parsed = toPortNumber(value);
          if (parsed !== null) ports.add(parsed);
        });
      }
    }
    byApp.set(appId, ports);
  }

  return byApp;
};

const getExplicitPortForRecord = ({
  appId,
  assignment,
  serviceName,
  target,
  protocol,
  ordinal,
}) => {
  if (!assignment) return null;
  if (typeof assignment === "number" || typeof assignment === "string") {
    if (ordinal !== 0) return null;
    return toPortNumber(assignment);
  }

  if (typeof assignment !== "object") return null;
  const byService = assignment.byService;
  if (byService && typeof byService === "object") {
    const keyWithProtocol = `${serviceName}:${target}/${protocol}`;
    const keyWithoutProtocol = `${serviceName}:${target}`;
    if (Object.prototype.hasOwnProperty.call(byService, keyWithProtocol)) {
      return toPortNumber(byService[keyWithProtocol]);
    }
    if (Object.prototype.hasOwnProperty.call(byService, keyWithoutProtocol)) {
      return toPortNumber(byService[keyWithoutProtocol]);
    }
  }

  const byContainerPort = assignment.byContainerPort;
  if (byContainerPort && typeof byContainerPort === "object") {
    const key = String(target);
    if (Object.prototype.hasOwnProperty.call(byContainerPort, key)) {
      return toPortNumber(byContainerPort[key]);
    }
  }

  if (ordinal === 0) {
    const primary = toPortNumber(assignment.primary);
    if (primary !== null) return primary;
  }
  return null;
};

const isPortAvailable = ({ occupiedPorts, port, appId, ownerKey }) => {
  const existing = occupiedPorts.get(port);
  if (!existing) return true;
  if (existing.ownerKey === ownerKey) return true;
  if (existing.type === "explicit-reserved" && existing.appId === appId) return true;
  return false;
};

const allocatePort = ({ occupiedPorts, ranges }) => {
  for (const range of ranges) {
    for (let port = range.start; port <= range.end; port += 1) {
      if (!occupiedPorts.has(port)) return port;
    }
  }
  throw new Error("No available host ports left in preferred ranges");
};

const findPrimaryPortForPortMap = (doc) => {
  const services = doc?.services;
  if (!services || typeof services !== "object") return null;
  const mainService = String(doc?.["x-casaos"]?.main || "");

  const serviceOrder = [];
  if (mainService && Object.prototype.hasOwnProperty.call(services, mainService)) {
    serviceOrder.push(mainService);
  }
  for (const name of Object.keys(services)) {
    if (!serviceOrder.includes(name)) serviceOrder.push(name);
  }

  for (const serviceName of serviceOrder) {
    const service = services[serviceName];
    if (!Array.isArray(service?.ports)) continue;
    for (const entry of service.ports) {
      if (typeof entry === "string") {
        const parsed = parsePortString(entry);
        if (parsed.parsable && parsed.hasPublished && parsed.published !== null) {
          return parsed.published;
        }
      } else if (entry && typeof entry === "object") {
        const published = toPortNumber(entry.published ?? entry.host_port ?? entry.hostPort);
        if (published !== null) return published;
      }
    }
  }
  return null;
};

const storagePolicy = readJson(STORAGE_POLICY_PATH);
const portPolicy = readJson(PORT_POLICY_PATH);

if (!fs.existsSync(APPS_DIR)) {
  throw new Error(`Apps directory not found: ${APPS_DIR}`);
}

const appIds = fs
  .readdirSync(APPS_DIR, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .filter((appId) => (appFilter ? appFilter.has(appId) : true))
  .sort((a, b) => a.localeCompare(b));

if (appIds.length === 0) {
  console.log("No apps matched the current scope.");
  process.exit(0);
}

const contexts = [];
for (const appId of appIds) {
  const composePath = path.join(APPS_DIR, appId, "docker-compose.yml");
  if (!fs.existsSync(composePath)) continue;

  const originalContent = fs.readFileSync(composePath, "utf8");
  const parsedDoc = yaml.load(originalContent);
  if (!parsedDoc || typeof parsedDoc !== "object") {
    throw new Error(`Invalid compose document: ${composePath}`);
  }

  contexts.push({
    appId,
    composePath,
    relativePath: path.relative(cwd, composePath),
    originalContent,
    doc: parsedDoc,
    hostNetwork: false,
    warnings: [],
    changes: {
      volumes: [],
      environment: [],
      ports: [],
      portMap: null,
    },
    volumeClassifications: {},
  });
}

for (const context of contexts) {
  context.hostNetwork = isAppHostNetwork({
    appId: context.appId,
    doc: context.doc,
    portPolicy,
  });
}

const beforePortRecords = contexts.flatMap((context) =>
  collectCurrentPortRecords({ appId: context.appId, doc: context.doc })
);
const conflictsBefore = buildConflictList(beforePortRecords);

const occupiedPorts = new Map();
const reservePort = (port, entry) => {
  if (port === null) return;
  if (!occupiedPorts.has(port)) {
    occupiedPorts.set(port, entry);
  }
};

const reservedHostPorts = Array.isArray(portPolicy?.reservedHostPorts)
  ? portPolicy.reservedHostPorts
  : [];
for (const reserved of reservedHostPorts) {
  const parsed = toPortNumber(reserved);
  if (parsed !== null) reservePort(parsed, { type: "reserved", ownerKey: `reserved:${parsed}` });
}

for (const context of contexts) {
  if (!context.hostNetwork) continue;
  const hostNetworkRecords = collectCurrentPortRecords({ appId: context.appId, doc: context.doc });
  for (const record of hostNetworkRecords) {
    reservePort(record.published, {
      type: "host-network",
      appId: context.appId,
      ownerKey: `${context.appId}:${record.serviceName}:${record.index}`,
    });
  }
  const hostNetworkPortMap = toPortNumber(context.doc?.["x-casaos"]?.port_map);
  if (hostNetworkPortMap !== null) {
    reservePort(hostNetworkPortMap, {
      type: "host-network-port-map",
      appId: context.appId,
      ownerKey: `${context.appId}:x-casaos.port_map`,
    });
  }
}

const explicitAssignments =
  portPolicy?.explicitAssignments && typeof portPolicy.explicitAssignments === "object"
    ? portPolicy.explicitAssignments
    : {};
const explicitAssignmentPorts = collectExplicitAssignmentPorts(explicitAssignments);
for (const [appId, ports] of explicitAssignmentPorts.entries()) {
  for (const port of ports) {
    reservePort(port, {
      type: "explicit-reserved",
      appId,
      ownerKey: `explicit:${appId}:${port}`,
    });
  }
}

const preferredRanges = rangesFromPolicy(portPolicy);

for (const context of contexts) {
  const { appId, doc } = context;
  let hasChange = false;

  for (const [serviceName, service] of getServiceEntries(doc)) {
    if (Array.isArray(service?.volumes)) {
      service.volumes.forEach((volumeEntry, index) => {
        if (typeof volumeEntry === "string") {
          const parsedVolume = parseVolumeString(volumeEntry);
          if (!parsedVolume) return;
          const rewritten = rewriteHostPath({
            appId,
            sourcePath: parsedVolume.source,
            containerPath: parsedVolume.target,
            storagePolicy,
          });

          context.volumeClassifications[rewritten.classification] =
            (context.volumeClassifications[rewritten.classification] ?? 0) + 1;

          if (!rewritten.changed) return;
          const updatedVolume = formatVolumeString({
            ...parsedVolume,
            source: rewritten.updatedPath,
          });
          service.volumes[index] = updatedVolume;
          context.changes.volumes.push({
            service: serviceName,
            index,
            classification: rewritten.classification,
            before: volumeEntry,
            after: updatedVolume,
          });
          hasChange = true;
          return;
        }

        if (!volumeEntry || typeof volumeEntry !== "object") return;
        const sourceKey = Object.prototype.hasOwnProperty.call(volumeEntry, "source")
          ? "source"
          : Object.prototype.hasOwnProperty.call(volumeEntry, "src")
            ? "src"
            : null;
        const targetKey = Object.prototype.hasOwnProperty.call(volumeEntry, "target")
          ? "target"
          : Object.prototype.hasOwnProperty.call(volumeEntry, "dst")
            ? "dst"
            : Object.prototype.hasOwnProperty.call(volumeEntry, "destination")
              ? "destination"
              : null;
        if (!sourceKey || !targetKey) return;
        const sourcePath = String(volumeEntry[sourceKey] ?? "");
        const containerPath = String(volumeEntry[targetKey] ?? "");
        if (!sourcePath || !containerPath) return;

        const rewritten = rewriteHostPath({
          appId,
          sourcePath,
          containerPath,
          storagePolicy,
        });
        context.volumeClassifications[rewritten.classification] =
          (context.volumeClassifications[rewritten.classification] ?? 0) + 1;
        if (!rewritten.changed) return;

        const beforeObject = JSON.stringify(volumeEntry);
        volumeEntry[sourceKey] = rewritten.updatedPath;
        context.changes.volumes.push({
          service: serviceName,
          index,
          classification: rewritten.classification,
          before: beforeObject,
          after: JSON.stringify(volumeEntry),
        });
        hasChange = true;
      });
    }

    if (Array.isArray(service?.environment)) {
      service.environment.forEach((entry, index) => {
        if (typeof entry !== "string") return;
        const separatorIndex = entry.indexOf("=");
        if (separatorIndex === -1) return;
        const key = entry.slice(0, separatorIndex);
        const value = entry.slice(separatorIndex + 1);
        const rewritten = rewritePathStringValue({ appId, value, storagePolicy });
        if (!rewritten.changed) return;
        const updated = `${key}=${rewritten.updated}`;
        service.environment[index] = updated;
        context.changes.environment.push({
          service: serviceName,
          key,
          index,
          before: entry,
          after: updated,
        });
        hasChange = true;
      });
    } else if (service?.environment && typeof service.environment === "object") {
      for (const [key, value] of Object.entries(service.environment)) {
        if (typeof value !== "string") continue;
        const rewritten = rewritePathStringValue({ appId, value, storagePolicy });
        if (!rewritten.changed) continue;
        service.environment[key] = rewritten.updated;
        context.changes.environment.push({
          service: serviceName,
          key,
          before: value,
          after: rewritten.updated,
        });
        hasChange = true;
      }
    }
  }

  if (!context.hostNetwork) {
    let appPortOrdinal = 0;
    for (const [serviceName, service] of getServiceEntries(doc)) {
      if (!Array.isArray(service?.ports)) continue;
      service.ports.forEach((portEntry, index) => {
        let parsed = null;
        let published = null;
        let target = null;
        let protocol = "tcp";

        if (typeof portEntry === "string") {
          parsed = parsePortString(portEntry);
          if (!parsed.parsable || !parsed.hasPublished || parsed.published === null) {
            if (!parsed.parsable && parsed.reason) {
              context.warnings.push(
                `${serviceName}.ports[${index}] skipped (${parsed.reason}): ${portEntry}`
              );
            }
            return;
          }
          published = parsed.published;
          target = parsed.target;
          protocol = parsed.protocol || "tcp";
        } else if (portEntry && typeof portEntry === "object") {
          published = toPortNumber(
            portEntry.published ?? portEntry.host_port ?? portEntry.hostPort
          );
          target = toPortNumber(
            portEntry.target ?? portEntry.container_port ?? portEntry.containerPort
          );
          protocol = String(portEntry.protocol || "tcp").toLowerCase();
          if (published === null || target === null) {
            context.warnings.push(
              `${serviceName}.ports[${index}] skipped (unparseable object port mapping)`
            );
            return;
          }
        } else {
          return;
        }

        const ownerKey = `${appId}:${serviceName}:${index}`;
        const explicitPort = getExplicitPortForRecord({
          appId,
          assignment: explicitAssignments[appId],
          serviceName,
          target,
          protocol,
          ordinal: appPortOrdinal,
        });

        let assignedPort = published;
        let reason = "keep-existing";
        if (explicitPort !== null) {
          if (
            !isPortAvailable({
              occupiedPorts,
              port: explicitPort,
              appId,
              ownerKey,
            })
          ) {
            context.warnings.push(
              `Explicit port ${explicitPort} unavailable for ${serviceName}:${target}/${protocol}; allocating next available`
            );
            assignedPort = allocatePort({ occupiedPorts, ranges: preferredRanges });
            reason = "allocate-range-explicit-conflict";
          } else {
            assignedPort = explicitPort;
            reason = "explicit-assignment";
          }
        } else if (
          !isPortAvailable({
            occupiedPorts,
            port: published,
            appId,
            ownerKey,
          })
        ) {
          assignedPort = allocatePort({ occupiedPorts, ranges: preferredRanges });
          reason = "allocate-range-conflict";
        }

        occupiedPorts.set(assignedPort, {
          type: "assigned",
          appId,
          ownerKey,
        });

        if (assignedPort !== published) {
          if (typeof portEntry === "string" && parsed) {
            service.ports[index] = formatPortString(parsed, assignedPort);
          } else if (portEntry && typeof portEntry === "object") {
            if (typeof portEntry.published === "number") {
              portEntry.published = assignedPort;
            } else {
              portEntry.published = String(assignedPort);
            }
          }
          context.changes.ports.push({
            service: serviceName,
            index,
            protocol,
            containerPort: target,
            before: published,
            after: assignedPort,
            reason,
          });
          hasChange = true;
        }
        appPortOrdinal += 1;
      });
    }
  }

  const primaryPort = findPrimaryPortForPortMap(doc);
  if (primaryPort !== null) {
    const currentPortMap = String(doc?.["x-casaos"]?.port_map ?? "");
    if (currentPortMap !== String(primaryPort)) {
      if (!doc["x-casaos"] || typeof doc["x-casaos"] !== "object") {
        doc["x-casaos"] = {};
      }
      doc["x-casaos"].port_map = String(primaryPort);
      context.changes.portMap = {
        before: currentPortMap || null,
        after: String(primaryPort),
      };
      hasChange = true;
    }
  }

  context.changed = hasChange;
}

let filesWritten = 0;
for (const context of contexts) {
  if (!context.changed) continue;
  const nextContent = `${yaml.dump(context.doc, {
    lineWidth: -1,
    noRefs: true,
    sortKeys: false,
  })}\n`;
  context.nextContent = nextContent;
  if (writeMode) {
    fs.writeFileSync(context.composePath, nextContent, "utf8");
    filesWritten += 1;
  }
}

const afterPortRecords = contexts.flatMap((context) =>
  collectCurrentPortRecords({ appId: context.appId, doc: context.doc })
);
const conflictsAfter = buildConflictList(afterPortRecords);

const summary = {
  mode: writeMode ? "write" : "dry-run",
  appsScanned: contexts.length,
  hostNetworkApps: contexts.filter((context) => context.hostNetwork).length,
  appsChanged: contexts.filter((context) => context.changed).length,
  filesWritten,
  volumesRewritten: contexts.reduce((sum, context) => sum + context.changes.volumes.length, 0),
  environmentValuesRewritten: contexts.reduce(
    (sum, context) => sum + context.changes.environment.length,
    0
  ),
  portsRewritten: contexts.reduce((sum, context) => sum + context.changes.ports.length, 0),
  portMapUpdates: contexts.reduce(
    (sum, context) => sum + (context.changes.portMap ? 1 : 0),
    0
  ),
  warnings: contexts.reduce((sum, context) => sum + context.warnings.length, 0),
  conflictsBefore: conflictsBefore.length,
  conflictsAfter: conflictsAfter.length,
};

const report = {
  generatedAt: new Date().toISOString(),
  summary,
  policies: {
    storage: path.relative(cwd, STORAGE_POLICY_PATH),
    ports: path.relative(cwd, PORT_POLICY_PATH),
  },
  conflicts: {
    before: conflictsBefore,
    after: conflictsAfter,
  },
  apps: contexts
    .filter((context) => context.changed || context.warnings.length > 0 || verbose)
    .map((context) => ({
      appId: context.appId,
      file: context.relativePath,
      hostNetwork: context.hostNetwork,
      volumeClassifications: context.volumeClassifications,
      changes: context.changes,
      warnings: context.warnings,
    })),
};

if (reportPathArg) {
  const outputPath = path.isAbsolute(reportPathArg)
    ? reportPathArg
    : path.join(cwd, reportPathArg);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  console.log(`Wrote report: ${path.relative(cwd, outputPath)}`);
}

console.log(`Mode: ${summary.mode}`);
console.log(`Apps scanned: ${summary.appsScanned}`);
console.log(`Host-network apps: ${summary.hostNetworkApps}`);
console.log(`Apps changed: ${summary.appsChanged}`);
console.log(`Volumes rewritten: ${summary.volumesRewritten}`);
console.log(`Environment values rewritten: ${summary.environmentValuesRewritten}`);
console.log(`Ports rewritten: ${summary.portsRewritten}`);
console.log(`x-casaos.port_map updates: ${summary.portMapUpdates}`);
console.log(`Port conflicts before: ${summary.conflictsBefore}`);
console.log(`Port conflicts after: ${summary.conflictsAfter}`);
console.log(`Warnings: ${summary.warnings}`);

if (conflictsBefore.length > 0) {
  console.log("");
  console.log("Conflicts before rewrite (sample):");
  conflictsBefore.slice(0, 20).forEach((conflict) => {
    console.log(`- ${conflict.port} (${conflict.holders.length} holders)`);
  });
}

if (conflictsAfter.length > 0) {
  console.log("");
  console.log("Conflicts after rewrite:");
  conflictsAfter.slice(0, 20).forEach((conflict) => {
    console.log(`- ${conflict.port} (${conflict.holders.length} holders)`);
  });
}

if (!verbose) {
  const previewApps = contexts
    .filter((context) => context.changed)
    .slice(0, 20)
    .map((context) => {
      const totalChanges =
        context.changes.volumes.length +
        context.changes.environment.length +
        context.changes.ports.length +
        (context.changes.portMap ? 1 : 0);
      return `- ${context.appId}: ${totalChanges} proposed change(s)`;
    });

  if (previewApps.length > 0) {
    console.log("");
    console.log("Deterministic preview (first 20 changed apps):");
    previewApps.forEach((line) => console.log(line));
  }
}

