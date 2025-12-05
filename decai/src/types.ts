import type { R2PipeSync } from "r2papi";

declare global {
  const r2: R2PipeSync;
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
  get: () => unknown;
  set: (v: string) => void;
}

export interface ConfigHandlers {
  [key: string]: ConfigHandler;
}

export type ApiKeyResult = [string | null, string | null, string];

export interface HttpResponse {
  error?: { message?: string } | string;
  choices?: Array<{ message: { content: string } }>;
  content?: Array<{ text: string }>;
  message?: { content: string };
  candidates?: Array<{ content: { parts: Array<{ text: string }> } }>;
  data?: Array<
    {
      id: string;
      name?: string;
      max_context_length?: number;
      description?: string;
    }
  >;
  models?: Array<{ name: string }>;
  [key: string]: unknown;
}

export type PayloadBuilder = (
  model: string,
  query: string,
  provider: ProviderConfig,
) => Record<string, unknown>;
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
