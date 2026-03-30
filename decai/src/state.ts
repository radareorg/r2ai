import { AppState } from "./types";
import { DEFAULT_PROMPT } from "./constants";

export const state: AppState = {
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
  think: -1,
  useFiles: false,
  contextFile: "",
  model: "",
  cache: false,
  maxInputTokens: -1,
  prompt: DEFAULT_PROMPT,
  lastOutput: "",
};
