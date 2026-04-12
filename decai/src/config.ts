import { ConfigHandler, ConfigHandlers } from "./types";
import { DECAI_CONFIG_DIR, DECAI_CONFIG_PATH } from "./constants";
import { defaultState, state } from "./state";
import { listModelsFor } from "./models";
import { listProviders } from "./providers";
import { formatHeaders, parseHeaders } from "./headers";
import { ensurePath, fileExists } from "./utils";

let rcConfigLoaded = false;

function parseBoolean(value: string): boolean {
  return value === "true" || value === "1";
}

type StateKey = keyof typeof state;

function boolHandler(key: StateKey): ConfigHandler {
  // deno-lint-ignore no-explicit-any
  const s = state as any;
  return {
    get: () => s[key] as boolean,
    set: (v: string) => { s[key] = parseBoolean(v); },
  };
}

function stringHandler(key: StateKey): ConfigHandler {
  // deno-lint-ignore no-explicit-any
  const s = state as any;
  return {
    get: () => s[key] as string,
    set: (v: string) => { s[key] = v; },
  };
}

export const configHandlers: ConfigHandlers = {
  pipeline: {
    get: () => state.pipeline,
    set: (v: string) => {
      state.pipeline = v;
      try {
        state.decopipe = JSON.parse(r2.cmd("cat " + v));
      } catch (e) {
        console.error(e);
      }
    },
  },
  model: {
    get: () => state.model,
    set: (v: string) => {
      if (v === "?") {
        listModelsFor(state.api);
      } else {
        state.model = v.trim();
      }
    },
  },
  deterministic: boolHandler("deterministic"),
  files: boolHandler("useFiles"),
  think: {
    get: () => state.think || "false",
    set: (v: string) => { state.think = v; },
  },
  debug: boolHandler("debug"),
  timeout: {
    get: () => state.timeout,
    set: (v: string) => { state.timeout = Math.max(0, parseInt(v, 10) || 0); },
  },
  api: {
    get: () => state.api,
    set: (v: string) => {
      if (v === "?") {
        console.error(listProviders().join("\n"));
      } else {
        state.api = v;
      }
    },
  },
  lang: stringHandler("language"),
  hlang: stringHandler("humanLanguage"),
  cache: boolHandler("cache"),
  cmds: stringHandler("commands"),
  tts: boolHandler("tts"),
  yolo: boolHandler("yolo"),
  prompt: stringHandler("prompt"),
  ctxfile: stringHandler("contextFile"),
  baseurl: stringHandler("baseurl"),
  headers: {
    get: () => formatHeaders(state.extraHeaders),
    set: (v: string) => { state.extraHeaders = parseHeaders(v); },
  },
  maxtokens: {
    get: () => state.maxInputTokens,
    set: (v: string) => { state.maxInputTokens = parseInt(v, 10) || -1; },
  },
};

function resetRcConfigState(): void {
  const keep = { host: state.host, port: state.port, lastOutput: state.lastOutput };
  Object.assign(state, defaultState, keep);
  state.decopipe = { ...defaultState.decopipe };
  state.extraHeaders = [...defaultState.extraHeaders];
}

function normalizeRcLine(line: string): string | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) {
    return null;
  }
  return trimmed.startsWith("decai -e ")
    ? trimmed.slice("decai -e ".length).trim()
    : trimmed;
}

export function evalConfig(arg: string): void {
  const eqIndex = arg.indexOf("=");
  const k = eqIndex === -1 ? arg : arg.slice(0, eqIndex);
  const v = eqIndex === -1 ? undefined : arg.slice(eqIndex + 1);
  const handler = configHandlers[k];

  if (!handler) {
    console.error("Unknown config key");
    return;
  }

  if (typeof v !== "undefined") {
    handler.set(v);
  } else {
    console.log(handler.get());
  }
}

export function listAllConfig(): void {
  Object.entries(configHandlers).forEach(([key, handler]) => {
    const value = handler.get();
    console.log("decai -e " + key + "=" + value);
  });
}

export function loadRcConfig(): void {
  resetRcConfigState();
  if (!fileExists(DECAI_CONFIG_PATH)) {
    return;
  }
  const rcFile = r2.call("cat " + DECAI_CONFIG_PATH);
  for (const line of rcFile.split(/\r?\n/)) {
    const rcLine = normalizeRcLine(line);
    if (rcLine && rcLine[0] != '#') {
      evalConfig(rcLine);
    }
  }
}

export function ensureRcConfigLoaded(): void {
  if (rcConfigLoaded) {
    return;
  }
  loadRcConfig();
  rcConfigLoaded = true;
}

export function editRcConfig(): void {
  ensurePath(DECAI_CONFIG_DIR, DECAI_CONFIG_PATH);
  r2.cmd("'ed " + DECAI_CONFIG_PATH);
  loadRcConfig();
  rcConfigLoaded = true;
}
