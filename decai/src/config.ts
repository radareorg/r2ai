import { ConfigHandlers } from "./types";
import { state } from "./state";
import { listModelsFor } from "./models";
import { listProviders } from "./providers";
import { formatHeaders, parseHeaders } from "./headers";

function parseBoolean(value: string): boolean {
  return value === "true" || value === "1";
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
  deterministic: {
    get: () => state.deterministic,
    set: (v: string) => {
      state.deterministic = parseBoolean(v);
    },
  },
  files: {
    get: () => state.useFiles,
    set: (v: string) => {
      state.useFiles = parseBoolean(v);
    },
  },
  think: {
    get: () => state.think,
    set: (v: string) => {
      state.think = v === "true" ? 1 : v === "false" ? 0 : +v;
    },
  },
  debug: {
    get: () => state.debug,
    set: (v: string) => {
      state.debug = parseBoolean(v);
    },
  },
  timeout: {
    get: () => state.timeout,
    set: (v: string) => {
      state.timeout = Math.max(0, parseInt(v, 10) || 0);
    },
  },
  api: {
    get: () => state.api,
    set: (v: string) => {
      if (v === "?") {
        const providersList = listProviders().join("\n");
        console.error(providersList);
      } else {
        state.api = v;
      }
    },
  },
  lang: {
    get: () => state.language,
    set: (v: string) => {
      state.language = v;
    },
  },
  hlang: {
    get: () => state.humanLanguage,
    set: (v: string) => {
      state.humanLanguage = v;
    },
  },
  cache: {
    get: () => state.cache,
    set: (v: string) => {
      state.cache = parseBoolean(v);
    },
  },
  cmds: {
    get: () => state.commands,
    set: (v: string) => {
      state.commands = v;
    },
  },
  tts: {
    get: () => state.tts,
    set: (v: string) => {
      state.tts = parseBoolean(v);
    },
  },
  yolo: {
    get: () => state.yolo,
    set: (v: string) => {
      state.yolo = parseBoolean(v);
    },
  },
  prompt: {
    get: () => state.prompt,
    set: (v: string) => {
      state.prompt = v;
    },
  },
  ctxfile: {
    get: () => state.contextFile,
    set: (v: string) => {
      state.contextFile = v;
    },
  },
  baseurl: {
    get: () => state.baseurl,
    set: (v: string) => {
      state.baseurl = v;
    },
  },
  headers: {
    get: () => formatHeaders(state.extraHeaders),
    set: (v: string) => {
      state.extraHeaders = parseHeaders(v);
    },
  },
  maxtokens: {
    get: () => state.maxInputTokens,
    set: (v: string) => {
      state.maxInputTokens = parseInt(v, 10) || -1;
    },
  },
};

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
