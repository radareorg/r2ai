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

function collectHeaders(
  headerLines: string[],
  into: Map<string, string>,
): void {
  for (const rawLine of headerLines) {
    const header = parseHeaderLine(rawLine.trim());
    if (header) {
      into.set(normalizeHeaderName(header.name), formatHeader(header));
    }
  }
}

export function parseHeaders(value: string): string[] {
  const headers = new Map<string, string>();
  const lines = value.replace(/\\n/g, "\n").split(/\r?\n/g)
    .filter((l) => { const t = l.trim(); return t && !t.startsWith("#"); });
  collectHeaders(lines, headers);
  return Array.from(headers.values());
}

export function formatHeaders(headers: string[]): string {
  return headers.join("\\n");
}

export function mergeHeaders(...groups: string[][]): string[] {
  const merged = new Map<string, string>();
  for (const group of groups) {
    collectHeaders(group, merged);
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
