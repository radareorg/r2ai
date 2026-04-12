import { AppState } from "./types";
import { DEFAULT_PROMPT } from "./constants";

export const defaultState: AppState = {
  decopipe: { use: false },
  host: "http://localhost",
  port: "11434",
  baseurl: "",
  extraHeaders: [],
  api: "ollama",
  pipeline: "",
  commands: "pdc",
  yolo: false,
  tts: false,
  language: "C",
  humanLanguage: "English",
  deterministic: true,
  debug: false,
  timeout: 180,
  think: "",
  useFiles: false,
  contextFile: "",
  model: "",
  cache: false,
  maxInputTokens: -1,
  prompt: DEFAULT_PROMPT,
  lastOutput: "",
};

export const state: AppState = {
  ...defaultState,
  decopipe: { ...defaultState.decopipe },
  extraHeaders: [...defaultState.extraHeaders],
};
