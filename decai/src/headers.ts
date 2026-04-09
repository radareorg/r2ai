import { state } from "./state";

const HEADER_ENV_VARS = ["DECAI_HEADERS", "R2AI_HEADERS"];

interface ParsedHeader {
  name: string;
  value: string;
}

function readEnvVar(name: string): string {
  const value = r2.cmd("'%" + name).trim();
  return value !== "" && !value.includes("=") ? value : "";
}

function normalizeHeaderName(name: string): string {
  return name.trim().toLowerCase();
}

function parseHeaderLine(line: string): ParsedHeader | null {
  const colon = line.indexOf(":");
  const equals = line.indexOf("=");
  const sep = colon !== -1 && (equals === -1 || colon < equals)
    ? colon
    : equals;

  if (sep === -1) {
    return null;
  }

  const name = line.slice(0, sep).trim();
  if (name === "") {
    return null;
  }

  return {
    name,
    value: line.slice(sep + 1).trim(),
  };
}

function formatHeader(header: ParsedHeader): string {
  return header.value === ""
    ? `${header.name}:`
    : `${header.name}: ${header.value}`;
}

export function parseHeaders(value: string): string[] {
  const headers = new Map<string, string>();
  const normalized = value.replace(/\\n/g, "\n");

  for (const rawLine of normalized.split(/\r?\n/g)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const header = parseHeaderLine(line);
    if (!header) {
      continue;
    }

    headers.set(normalizeHeaderName(header.name), formatHeader(header));
  }

  return Array.from(headers.values());
}

export function formatHeaders(headers: string[]): string {
  return headers.join("\\n");
}

export function mergeHeaders(...groups: string[][]): string[] {
  const merged = new Map<string, string>();

  for (const group of groups) {
    for (const rawHeader of group) {
      const header = parseHeaderLine(rawHeader);
      if (!header) {
        continue;
      }
      merged.set(normalizeHeaderName(header.name), formatHeader(header));
    }
  }

  return Array.from(merged.values());
}

function readConfiguredEnvHeaders(): string[] {
  for (const name of HEADER_ENV_VARS) {
    const value = readEnvVar(name);
    if (value) {
      return parseHeaders(value);
    }
  }
  return [];
}

export function getConfiguredHeaders(): string[] {
  return mergeHeaders(readConfiguredEnvHeaders(), state.extraHeaders);
}
