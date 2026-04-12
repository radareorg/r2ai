import {
  ApiKeyResult,
  ApiStyle,
  AuthStyle,
  HttpResponse,
  JsonObject,
  ModelDataEntry,
  OllamaModelEntry,
  ProviderConfig,
  ProviderRegistry,
} from "./types";
import { state } from "./state";
import { filterResponse, padRight } from "./utils";
import { getApiKey } from "./apiKeys";
import { getConfiguredHeaders, mergeHeaders } from "./headers";
import { httpGet, httpPost } from "./http";

interface ProviderRuntime {
  buildPayload: (model: string, query: string) => JsonObject;
  parseResponse: (response: HttpResponse) => string;
  buildUrl: (baseUrl: string, model: string, apiKey?: string) => string;
  requiresUrlApiKey?: boolean;
}

function getApiKeyName(authKey: string): string {
  return authKey.split("_")[0].toLowerCase();
}

function readProviderKey(provider: ProviderConfig): ApiKeyResult | undefined {
  if (!provider.authKey) {
    return undefined;
  }
  const keyNames = Array.from(
    new Set(
      [provider.keyName, getApiKeyName(provider.authKey)].filter(Boolean),
    ),
  ) as string[];

  let fallback: ApiKeyResult | undefined;
  for (const keyName of keyNames) {
    const result = getApiKey(keyName, provider.authKey);
    if (result[0]) {
      return result;
    }
    if (!fallback && result[2] !== "nope") {
      fallback = result;
    }
  }

  return fallback ||
    getApiKey(getApiKeyName(provider.authKey), provider.authKey);
}

function getErrorMessage(error: HttpResponse["error"]): string | undefined {
  if (!error) {
    return undefined;
  }
  return typeof error === "string" ? error : error.message;
}

function getProviderBaseUrl(provider: ProviderConfig): string {
  return state.baseurl || provider.defaultBaseUrl;
}

function getProviderHeaders(
  providerHeaders: string[],
  extraHeaders: string[] = getConfiguredHeaders(),
): string[] {
  return mergeHeaders(providerHeaders, extraHeaders);
}

function buildBearerHeaders(apiKey: string | null): string[] {
  return apiKey ? ["Authorization: Bearer " + apiKey] : [];
}

function buildAnthropicHeaders(apiKey: string | null): string[] {
  const headers = ["anthropic-version: 2023-06-01"];
  return apiKey ? mergeHeaders(headers, ["x-api-key: " + apiKey]) : headers;
}

function buildAuthHeaders(
  provider: ProviderConfig,
  apiKey: string | null,
): string[] {
  const authStyle: AuthStyle = provider.authStyle || "none";
  switch (authStyle) {
    case "bearer":
      return buildBearerHeaders(apiKey);
    case "anthropic":
      return buildAnthropicHeaders(apiKey);
    case "none":
    default:
      return [];
  }
}

function listDataModels(
  url: string,
  headers: string[],
  mapper: (model: ModelDataEntry) => string,
): string {
  const response = httpGet(url, headers);
  const error = getErrorMessage(response.error);
  if (error) {
    console.error(error);
    return "error invalid response";
  }
  return response.data?.map(mapper).join("\n") || "";
}

function uniqueBy<T>(items: T[], getKey: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = getKey(item);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function listOpenAIModels(provider: ProviderConfig): string {
  const apiKey = readProviderKey(provider);
  const baseUrl = getProviderBaseUrl(provider);
  const headers = getProviderHeaders(
    buildAuthHeaders(provider, apiKey?.[0] || null),
  );
  return listDataModels(
    baseUrl + "/v1/models",
    headers,
    (model) => model.id,
  );
}

function listAnthropicModels(provider: ProviderConfig): string {
  const apiKey = readProviderKey(provider);
  const baseUrl = getProviderBaseUrl(provider);
  const headers = getProviderHeaders(
    buildAuthHeaders(provider, apiKey?.[0] || null),
  );
  return listDataModels(
    baseUrl + "/v1/models",
    headers,
    (model) => model.id,
  );
}

function listOllamaModels(provider: ProviderConfig): string {
  const response = httpGet(
    getProviderBaseUrl(provider) + "/api/tags",
    getProviderHeaders(
      buildAuthHeaders(provider, readProviderKey(provider)?.[0] || null),
    ),
  );
  const error = getErrorMessage(response.error);
  if (error) {
    console.error(error);
    return "error invalid response";
  }
  return response.models?.map((model: OllamaModelEntry) => model.name).join(
    "\n",
  ) || "";
}

function listMistralModels(provider: ProviderConfig): string {
  const apiKey = readProviderKey(provider);
  const response = httpGet(
    getProviderBaseUrl(provider) + "/v1/models",
    getProviderHeaders(buildAuthHeaders(provider, apiKey?.[0] || null)),
  );
  if (response.data) {
    return uniqueBy(response.data, (model) => model.name || model.id)
      .map((model) =>
        [
          padRight(model.name || model.id, 30),
          padRight("" + (model.max_context_length || ""), 10),
          model.description || "",
        ].join(" ")
      )
      .join("\n");
  }
  return "";
}

const providerRuntimes: Record<ApiStyle, ProviderRuntime> = {
  openai: {
    buildPayload: (model, query) => ({
      stream: false,
      model,
      messages: [{ role: "user", content: query }],
    }),
    parseResponse: (response) => {
      if (response.error) {
        const error = typeof response.error === "object"
          ? response.error.message
          : response.error;
        throw new Error(error || "Unknown error");
      }
      if (response.choices && response.choices[0]?.message?.content) {
        return filterResponse(response.choices[0].message.content);
      }
      throw new Error("Invalid response format");
    },
    buildUrl: (baseUrl) => baseUrl + "/v1/chat/completions",
  },
  anthropic: {
    buildPayload: (model, query) => {
      const payload: {
        model: string;
        max_tokens: number;
        messages: Array<{ role: string; content: string }>;
        thinking?: { type: string; budget_tokens?: number };
        temperature?: number;
        top_p?: number;
        top_k?: number;
      } = {
        model,
        max_tokens: 5128,
        messages: [{ role: "user", content: query }],
      };
      if (isThinkEnabled()) {
        payload.thinking = { type: "enabled", budget_tokens: 4096 };
        payload.max_tokens = 16000;
      }
      if (state.deterministic && !isThinkEnabled()) {
        Object.assign(payload, { temperature: 0, top_p: 0, top_k: 1 });
      }
      return payload;
    },
    parseResponse: (response) => {
      if (response.content && Array.isArray(response.content)) {
        const parts: string[] = [];
        for (const block of response.content as Array<Record<string, unknown>>) {
          if (block.text) {
            parts.push(block.text as string);
          }
        }
        if (parts.length > 0) {
          return filterResponse(parts.join("\n"));
        }
      }
      if (response.error) {
        const error = typeof response.error === "object"
          ? response.error.message
          : response.error;
        throw new Error(error || "Unknown error");
      }
      throw new Error("Invalid response format");
    },
    buildUrl: (baseUrl) => baseUrl + "/v1/messages",
  },
  ollama: {
    buildPayload: (model, query) => {
      const payload: {
        stream: boolean;
        model: string;
        messages: Array<{ role: string; content: string }>;
        think?: boolean | string;
        options?: {
          repeat_last_n: number;
          top_p: number;
          top_k: number;
          temperature: number;
          repeat_penalty: number;
          seed: number;
        };
      } = {
        stream: false,
        model,
        messages: [{ role: "user", content: query }],
      };
      if (isThinkEnabled()) {
        if (state.think === "true" || state.think === "1") {
          payload.think = true;
        } else {
          // Pass reasoning levels like "low", "medium", "high" as-is
          payload.think = state.think;
        }
      } else {
        // Disable thinking by default — models like glm-5 enable it
        // implicitly, generating thousands of reasoning tokens
        payload.think = false;
      }
      if (state.deterministic) {
        payload.options = {
          repeat_last_n: 0,
          top_p: 1.0,
          top_k: 1.0,
          temperature: 0.0,
          repeat_penalty: 1.0,
          seed: 123,
        };
      }
      return payload;
    },
    parseResponse: (response) => {
      if (response.error) {
        const error = typeof response.error === "string"
          ? response.error
          : JSON.stringify(response.error);
        throw new Error(error);
      }
      if (response.message?.content) {
        return filterResponse(response.message.content);
      }
      throw new Error(JSON.stringify(response));
    },
    buildUrl: (baseUrl) => baseUrl + "/api/chat",
  },
  gemini: {
    buildPayload: (_model, query) => {
      const payload: {
        contents: Array<{ parts: Array<{ text: string }> }>;
        generationConfig?: Record<string, unknown>;
      } = {
        contents: [{ parts: [{ text: query }] }],
      };
      const genConfig: Record<string, unknown> = {};
      if (state.deterministic) {
        Object.assign(genConfig, { temperature: 0.0, topP: 1.0, topK: 1 });
      }
      if (state.think !== "") {
        if (isThinkDisabled()) {
          genConfig.thinkingConfig = { thinkingBudget: 0 };
        } else {
          genConfig.thinkingConfig = { thinkingBudget: 8192 };
        }
      }
      if (Object.keys(genConfig).length > 0) {
        payload.generationConfig = genConfig;
      }
      return payload;
    },
    parseResponse: (response) => {
      if (response.candidates && response.candidates[0]?.content?.parts) {
        const parts = response.candidates[0].content.parts as Array<Record<string, unknown>>;
        const textParts = parts
          .filter((p) => !p.thought && p.text)
          .map((p) => p.text as string);
        if (textParts.length > 0) {
          return filterResponse(textParts.join("\n"));
        }
      }
      if (response.error) {
        throw new Error(
          typeof response.error === "string"
            ? response.error
            : JSON.stringify(response.error),
        );
      }
      console.log(JSON.stringify(response));
      throw new Error("Invalid response format");
    },
    buildUrl: (baseUrl, model, apiKey) =>
      `${baseUrl}/v1beta/models/${model}:generateContent?key=${apiKey}`,
    requiresUrlApiKey: true,
  },
};

export const providerRegistry: ProviderRegistry = {
  anthropic: {
    defaultModel: "claude-3-7-sonnet-20250219",
    defaultBaseUrl: "https://api.anthropic.com",
    authKey: "ANTHROPIC_API_KEY",
    keyName: "anthropic",
    authStyle: "anthropic",
    apiStyle: "anthropic",
  },
  claude: {
    defaultModel: "claude-3-7-sonnet-20250219",
    defaultBaseUrl: "https://api.anthropic.com",
    authKey: "ANTHROPIC_API_KEY",
    keyName: "claude",
    authStyle: "anthropic",
    apiStyle: "anthropic",
  },
  openai: {
    defaultModel: "gpt-4o-mini",
    defaultBaseUrl: "https://api.openai.com",
    authKey: "OPENAI_API_KEY",
    authStyle: "bearer",
    apiStyle: "openai",
  },
  ollama: {
    defaultModel: "qwen2.5-coder:latest",
    defaultBaseUrl: "http://localhost:11434",
    authStyle: "none",
    apiStyle: "ollama",
  },
  ollamacloud: {
    defaultModel: "gpt-oss:120b",
    defaultBaseUrl: "https://ollama.com",
    authKey: "OLLAMA_API_KEY",
    keyName: "ollamacloud",
    authStyle: "bearer",
    apiStyle: "ollama",
  },
  opencode: {
    defaultModel: "big-pickle",
    defaultBaseUrl: "https://opencode.ai/zen",
    authKey: "OPENCODE_API_KEY",
    keyName: "opencode",
    authStyle: "bearer",
    apiStyle: "openai",
    hardcodedModels: ["big-pickle", "glm-5", "kimi-k2.5"],
  },
  zen: {
    defaultModel: "big-pickle",
    defaultBaseUrl: "https://opencode.ai/zen",
    authKey: "OPENCODE_API_KEY",
    keyName: "zen",
    authStyle: "bearer",
    apiStyle: "openai",
    hardcodedModels: ["big-pickle", "glm-5", "kimi-k2.5"],
  },
  gemini: {
    defaultModel: "gemini-2.5-flash",
    defaultBaseUrl: "https://generativelanguage.googleapis.com",
    authKey: "GEMINI_API_KEY",
    authStyle: "none",
    apiStyle: "gemini",
    hardcodedModels: [
      "gemini-2.0-flash",
      "gemini-2.0-flash-lite",
      "gemini-2.5-pro",
      "gemini-2.5-flash",
      "gemini-2.5-flash-lite",
    ],
  },
  mistral: {
    defaultModel: "codestral-latest",
    defaultBaseUrl: "https://api.mistral.ai",
    authKey: "MISTRAL_API_KEY",
    authStyle: "bearer",
    apiStyle: "openai",
  },
  xai: {
    defaultModel: "grok-beta",
    defaultBaseUrl: "https://api.x.ai",
    authKey: "XAI_API_KEY",
    authStyle: "bearer",
    apiStyle: "openai",
    hardcodedModels: ["grok-2", "grok-beta"],
  },
  lmstudio: {
    defaultModel: "local-model",
    defaultBaseUrl: "http://127.0.0.1:1234",
    authStyle: "none",
    apiStyle: "openai",
  },
  deepseek: {
    defaultModel: "deepseek-coder",
    defaultBaseUrl: "https://api.deepseek.com",
    authKey: "DEEPSEEK_API_KEY",
    authStyle: "bearer",
    apiStyle: "openai",
    hardcodedModels: ["deepseek-coder", "deepseek-chat"],
  },
  openrouter: {
    defaultModel: "openai/gpt-4o-mini",
    defaultBaseUrl: "https://openrouter.ai/api",
    authKey: "OPENROUTER_API_KEY",
    authStyle: "bearer",
    apiStyle: "openai",
  },
  groq: {
    defaultModel: "llama-3.3-70b-versatile",
    defaultBaseUrl: "https://api.groq.com/openai",
    authKey: "GROQ_API_KEY",
    authStyle: "bearer",
    apiStyle: "openai",
  },
};

export function getProvider(api: string): ProviderConfig | undefined {
  return providerRegistry[api];
}

export function listProviders(): string[] {
  return Object.keys(providerRegistry);
}

export function listModels(providerName: string): string {
  const provider = getProvider(providerName);
  if (!provider) {
    throw new Error(`Unknown provider: ${providerName}`);
  }

  if (providerName === "mistral") {
    return listMistralModels(provider);
  }

  switch (provider.apiStyle) {
    case "openai":
      return listOpenAIModels(provider);
    case "anthropic":
      return listAnthropicModels(provider);
    case "ollama":
      return listOllamaModels(provider);
    case "gemini":
      return "";
    default:
      return "";
  }
}

function isThinkDisabled(): boolean {
  return state.think === "false" || state.think === "0";
}

function isThinkEnabled(): boolean {
  return state.think !== "" && !isThinkDisabled();
}

function buildQuery(msg: string, hideprompt: boolean, apiStyle: ApiStyle): string {
  let query = msg;

  // Only add prompt-based thinking hints for APIs without native think support
  if (state.think !== "" && apiStyle === "openai") {
    if (isThinkDisabled()) {
      query +=
        ' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".';
      query += " /no_think";
    } else {
      query =
        "Think step by step and explain the reasoning process, When answering, first output your reasoning inside <think> and </think> tags, then give the final answer." +
        query;
    }
  }

  return hideprompt ? query : state.prompt + languagePrompt() + query;
}

function languagePrompt(): string {
  return "\n.Translate the code into " + state.language +
    " programming language\n";
}

function callRuntime(
  provider: ProviderConfig,
  runtime: ProviderRuntime,
  msg: string,
  hideprompt: boolean,
): string {
  const model = state.model || provider.defaultModel;
  const query = buildQuery(msg, hideprompt, provider.apiStyle);
  const apiKey = readProviderKey(provider);

  if (runtime.requiresUrlApiKey && apiKey?.[1] && provider.authKey) {
    return `Cannot read ~/.r2ai.${getApiKeyName(provider.authKey)}-key`;
  }

  const payload = runtime.buildPayload(model, query);
  const authHeaders = buildAuthHeaders(provider, apiKey?.[0] || null);
  if (provider.apiStyle === "ollama") {
    authHeaders.push("Accept: application/x-ndjson");
  }
  const headers = getProviderHeaders(authHeaders);
  const url = runtime.buildUrl(
    getProviderBaseUrl(provider),
    model,
    apiKey?.[0] || undefined,
  );

  try {
    return runtime.parseResponse(
      httpPost(url, headers, JSON.stringify(payload)),
    );
  } catch (error) {
    return "ERROR: " + (error as Error).message;
  }
}

export function callProvider(msg: string, hideprompt: boolean): string {
  const provider = getProvider(state.api);
  if (!provider) {
    return `Unknown value for 'decai -e api'. Available: ${
      listProviders().join(", ")
    }`;
  }

  return callRuntime(
    provider,
    providerRuntimes[provider.apiStyle],
    msg,
    hideprompt,
  );
}
