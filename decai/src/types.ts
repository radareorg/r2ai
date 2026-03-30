import type { R2PipeSync } from "./r2pipe";

interface ConsoleLike {
  log: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
}

declare global {
  const r2: R2PipeSync;
  const console: ConsoleLike;
  function btoa(str: string): string;
}

export type ApiStyle = "openai" | "anthropic" | "ollama" | "gemini";

export interface ProviderConfig {
  defaultModel: string;
  defaultBaseurl: string;
  requiresAuth: boolean;
  authKey?: string;
  apiStyle: ApiStyle;
  hardcodedModels?: string[];
  listModelsCallback?: (provider: ProviderConfig) => string;
}

export interface ProviderRegistry {
  [key: string]: ProviderConfig;
}

export interface DecoPipeConfig {
  use: boolean;
  default?: string;
  [key: string]: unknown;
}

export interface AppState {
  decopipe: DecoPipeConfig;
  host: string;
  port: string;
  baseurl: string;
  api: string;
  pipeline: string;
  commands: string;
  yolo: boolean;
  tts: boolean;
  language: string;
  humanLanguage: string;
  deterministic: boolean;
  debug: boolean;
  think: number;
  useFiles: boolean;
  contextFile: string;
  model: string;
  cache: boolean;
  maxInputTokens: number;
  prompt: string;
  lastOutput: string;
}

export interface ConfigHandler {
  get: () => string | number | boolean;
  set: (v: string) => void;
}

export interface ConfigHandlers {
  [key: string]: ConfigHandler;
}

export type ApiKeyResult = [string | null, string | null, string];

export interface ApiError {
  message?: string;
  [key: string]: unknown;
}

export interface OpenAIChoice {
  message?: {
    content?: string;
  };
}

export interface AnthropicContentBlock {
  text?: string;
}

export interface OllamaMessage {
  content?: string;
}

export interface GeminiPart {
  text?: string;
}

export interface GeminiCandidate {
  content?: {
    parts?: GeminiPart[];
  };
}

export interface ModelDataEntry {
  id: string;
  name?: string;
  max_context_length?: number;
  description?: string;
}

export interface OllamaModelEntry {
  name: string;
}

export interface HttpResponse {
  error?: ApiError | string;
  choices?: OpenAIChoice[];
  content?: AnthropicContentBlock[];
  message?: OllamaMessage;
  candidates?: GeminiCandidate[];
  data?: ModelDataEntry[];
  models?: OllamaModelEntry[];
  result?: string;
  [key: string]: unknown;
}

export type JsonObject = Record<string, unknown>;

export type PayloadBuilder = (
  model: string,
  query: string,
  provider: ProviderConfig,
) => JsonObject;
export type ResponseParser = (res: HttpResponse) => string;
export type UrlBuilder = (base: string, model: string, key?: string) => string;
export type HeadersBuilder = (
  key: string | null,
  provider: ProviderConfig,
) => string[];

export interface AutoReply {
  action: string;
  command?: string;
  description?: string;
  reason?: string;
  response?: string;
}
