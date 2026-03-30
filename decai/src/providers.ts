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
        temperature?: number;
        top_p?: number;
        top_k?: number;
      } = {
        model,
        max_tokens: 5128,
        messages: [{ role: "user", content: query }],
      };
      if (state.deterministic) {
        Object.assign(payload, { temperature: 0, top_p: 0, top_k: 1 });
      }
      return payload;
    },
    parseResponse: (response) => {
      if (response.content && response.content[0]?.text) {
        return filterResponse(response.content[0].text);
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
    buildPayload: (model, query) => {
      const payload: {
        contents: Array<{ parts: Array<{ text: string }> }>;
        generationConfig?: {
          temperature: number;
          topP: number;
          topK: number;
        };
      } = {
        contents: [{ parts: [{ text: query }] }],
      };
      if (state.deterministic) {
        payload.generationConfig = {
          temperature: 0.0,
          topP: 1.0,
          topK: 1,
        };
      }
      return payload;
    },
    parseResponse: (response) => {
      if (
        response.candidates &&
        response.candidates[0]?.content?.parts?.[0]?.text
      ) {
        return filterResponse(response.candidates[0].content.parts[0].text);
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

function buildQuery(msg: string, hideprompt: boolean): string {
  let query = msg;

  if (state.think >= 0) {
    if (state.think === 0) {
      query +=
        ' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".';
      query += " /no_think";
    } else if (state.think > 0) {
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
  const query = buildQuery(msg, hideprompt);
  const apiKey = readProviderKey(provider);

  if (runtime.requiresUrlApiKey && apiKey?.[1] && provider.authKey) {
    return `Cannot read ~/.r2ai.${getApiKeyName(provider.authKey)}-key`;
  }

  const payload = runtime.buildPayload(model, query);
  const headers = getProviderHeaders(
    buildAuthHeaders(provider, apiKey?.[0] || null),
  );
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
