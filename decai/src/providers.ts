import {
  ApiKeyResult,
  HeadersBuilder,
  PayloadBuilder,
  ProviderConfig,
  ProviderRegistry,
  ResponseParser,
  UrlBuilder,
} from "./types";
import { state } from "./state";
import { filterResponse, padRight } from "./utils";
import { getApiKey } from "./apiKeys";
import { httpGet, httpPost } from "./http";

const listOllamaModels = (provider: ProviderConfig): string => {
  const base = state.baseurl || state.host + ":" + state.port;
  const cmd = `curl -s ${base}/api/tags`;
  const res = r2.syscmds(cmd);
  try {
    const parsed = JSON.parse(res);
    if (parsed.models) {
      return parsed.models.map((model: { name: string }) => model.name).join(
        "\n",
      );
    }
  } catch (e) {
    console.error(e);
    console.log(res);
    return "error invalid response";
  }
  return "";
};

const listOpenAIModels = (provider: ProviderConfig): string => {
  let key: ApiKeyResult | undefined;
  if (provider.requiresAuth && provider.authKey) {
    key = getApiKey(
      provider.authKey.split("_")[0].toLowerCase(),
      provider.authKey,
    );
    if (key && key[1]) throw new Error(key[1]);
  }
  const base = state.baseurl || provider.defaultBaseurl;
  const url = base + "/v1/models";
  const headers = key ? ["Authorization: Bearer " + key[0]] : [];
  const response = httpGet(url, headers) as any;
  if (response.data) {
    return response.data.map((model: any) => model.id).join("\n");
  }
  return "";
};

const listAnthropicModels = (provider: ProviderConfig): string => {
  const key = getApiKey("anthropic", "ANTHROPIC_API_KEY");
  if (key && key[1]) throw new Error(key[1]);
  const base = state.baseurl || provider.defaultBaseurl;
  const url = base + "/v1/models";
  const headers = ["x-api-key: " + key[0], "anthropic-version: 2023-06-01"];
  const response = httpGet(url, headers) as any;
  if (response.data) {
    return response.data.map((model: any) => model.id).join("\n");
  }
  return "";
};

const listMistralModels = (provider: ProviderConfig): string => {
  const key = getApiKey("mistral", "MISTRAL_API_KEY");
  if (key && key[1]) throw new Error(key[1]);
  const base = state.baseurl || provider.defaultBaseurl;
  const url = base + "/v1/models";
  const headers = ["Authorization: Bearer " + key[0]];
  const response = httpGet(url, headers) as any;
  if (response.data) {
    const uniqByName = (arr: any[]) =>
      arr.filter((obj, i, self) =>
        self.findIndex((o) => o.name === obj.name) === i
      );
    return uniqByName(response.data)
      .map((model: any) =>
        [
          padRight(model.name || model.id, 30),
          padRight("" + (model.max_context_length || ""), 10),
          model.description || "",
        ].join(" ")
      )
      .join("\n");
  }
  return "";
};

export const providerRegistry: ProviderRegistry = {
  anthropic: {
    defaultModel: "claude-3-7-sonnet-20250219",
    defaultBaseurl: "https://api.anthropic.com",
    requiresAuth: true,
    authKey: "ANTHROPIC_API_KEY",
    apiStyle: "anthropic",
    hardcodedModels: [
      "claude-3-5-sonnet-20241022",
      "claude-3-7-sonnet-20250219",
      "claude-opus-4-20250514",
      "claude-sonnet-4-20250514",
    ],
    listModelsCallback: listAnthropicModels,
  },
  claude: {
    defaultModel: "claude-3-7-sonnet-20250219",
    defaultBaseurl: "https://api.anthropic.com",
    requiresAuth: true,
    authKey: "ANTHROPIC_API_KEY",
    apiStyle: "anthropic",
    hardcodedModels: [
      "claude-3-5-sonnet-20241022",
      "claude-3-7-sonnet-20250219",
      "claude-opus-4-20250514",
      "claude-sonnet-4-20250514",
    ],
    listModelsCallback: listAnthropicModels,
  },
  openai: {
    defaultModel: "gpt-4o-mini",
    defaultBaseurl: "https://api.openai.com",
    requiresAuth: true,
    authKey: "OPENAI_API_KEY",
    apiStyle: "openai",
    listModelsCallback: listOpenAIModels,
  },
  ollama: {
    defaultModel: "qwen2.5-coder:latest",
    defaultBaseurl: "http://localhost:11434",
    requiresAuth: false,
    apiStyle: "ollama",
    listModelsCallback: listOllamaModels,
  },
  ollamacloud: {
    defaultModel: "gpt-oss:120b",
    defaultBaseurl: "https://ollama.com",
    requiresAuth: true,
    authKey: "OLLAMA_API_KEY",
    apiStyle: "openai",
    listModelsCallback: listOpenAIModels,
  },
  gemini: {
    defaultModel: "gemini-2.5-flash",
    defaultBaseurl: "https://generativelanguage.googleapis.com",
    requiresAuth: true,
    authKey: "GEMINI_API_KEY",
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
    defaultBaseurl: "https://api.mistral.ai",
    requiresAuth: true,
    authKey: "MISTRAL_API_KEY",
    apiStyle: "openai",
    hardcodedModels: ["codestral-latest"],
    listModelsCallback: listMistralModels,
  },
  xai: {
    defaultModel: "grok-beta",
    defaultBaseurl: "https://api.x.ai",
    requiresAuth: true,
    authKey: "XAI_API_KEY",
    apiStyle: "openai",
    hardcodedModels: ["grok-2", "grok-beta"],
  },
  lmstudio: {
    defaultModel: "local-model",
    defaultBaseurl: "http://127.0.0.1:1234",
    requiresAuth: false,
    apiStyle: "openai",
    hardcodedModels: ["local-model"],
    listModelsCallback: listOpenAIModels,
  },
  deepseek: {
    defaultModel: "deepseek-coder",
    defaultBaseurl: "https://api.deepseek.com",
    requiresAuth: true,
    authKey: "DEEPSEEK_API_KEY",
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

function handleProvider(
  provider: ProviderConfig,
  msg: string,
  hideprompt: boolean,
  payloadBuilder: PayloadBuilder,
  responseParser: ResponseParser,
  urlBuilder: UrlBuilder,
  headersBuilder: HeadersBuilder,
): string {
  const model = state.model || provider.defaultModel;
  const query = buildQuery(msg, hideprompt);

  let key: ApiKeyResult | undefined;
  if (provider.requiresAuth && provider.authKey) {
    key = getApiKey(
      provider.authKey.split("_")[0].toLowerCase(),
      provider.authKey,
    );
    if (key[1]) {
      return `Cannot read ~/.r2ai.${
        provider.authKey.split("_")[0].toLowerCase()
      }-key`;
    }
  }

  const payload = payloadBuilder(model, query, provider);
  const base = state.baseurl || provider.defaultBaseurl;
  const url = urlBuilder(base, model, key && key[0] ? key[0] : undefined);
  const headers = headersBuilder(key ? key[0] : null, provider);

  try {
    const res = httpPost(url, headers, JSON.stringify(payload));
    return responseParser(res);
  } catch (e) {
    const err = e as Error;
    return "ERROR: " + err.message;
  }
}

export function handleOpenAI(
  provider: ProviderConfig,
  msg: string,
  hideprompt: boolean,
): string {
  const payloadBuilder: PayloadBuilder = (model, query) => ({
    stream: false,
    model,
    messages: [{ role: "user", content: query }],
  });

  const responseParser: ResponseParser = (res) => {
    if (res.error && typeof res.error === "object" && res.error.message) {
      throw new Error(res.error.message);
    }
    if (res.choices && res.choices[0]?.message?.content) {
      return filterResponse(res.choices[0].message.content);
    }
    throw new Error("Invalid response format");
  };

  const urlBuilder: UrlBuilder = (base, model) => base + "/v1/chat/completions";

  const headersBuilder: HeadersBuilder = (key) =>
    key ? ["Authorization: Bearer " + key] : [];

  return handleProvider(
    provider,
    msg,
    hideprompt,
    payloadBuilder,
    responseParser,
    urlBuilder,
    headersBuilder,
  );
}

export function handleAnthropic(
  provider: ProviderConfig,
  msg: string,
  hideprompt: boolean,
): string {
  if (!provider.authKey) {
    return "ERROR: No auth key configured";
  }

  const payloadBuilder: PayloadBuilder = (model, query) => {
    const payload: Record<string, unknown> = {
      model,
      max_tokens: 5128,
      messages: [{ role: "user", content: query }],
    };
    if (state.deterministic) {
      Object.assign(payload, { temperature: 0, top_p: 0, top_k: 1 });
    }
    return payload;
  };

  const responseParser: ResponseParser = (res) => {
    if (res.content && res.content[0]?.text) {
      return filterResponse(res.content[0].text);
    }
    if (res.error) {
      const errMsg = typeof res.error === "object"
        ? res.error.message
        : res.error;
      throw new Error(errMsg || "Unknown error");
    }
    throw new Error("Invalid response format");
  };
  const urlBuilder: UrlBuilder = (base, model) => base + "/v1/messages";
  const headersBuilder: HeadersBuilder = (
    key,
  ) => ["anthropic-version: 2023-06-01", "x-api-key: " + key];
  return handleProvider(
    provider,
    msg,
    hideprompt,
    payloadBuilder,
    responseParser,
    urlBuilder,
    headersBuilder,
  );
}

export function handleOllama(
  provider: ProviderConfig,
  msg: string,
  hideprompt: boolean,
): string {
  const payloadBuilder: PayloadBuilder = (model, query) => {
    const payload: Record<string, unknown> = {
      stream: false,
      model,
      messages: [{ role: "user", content: query }],
    };
    if (state.deterministic) {
      payload.options = {
        repeat_last_n: 0,
        top_p: 0.0,
        top_k: 1.0,
        temperature: 0.0,
        repeat_penalty: 1.0,
        seed: 123,
      };
    }
    return payload;
  };

  const responseParser: ResponseParser = (res) => {
    if (res && res.error) {
      const errMsg = typeof res.error === "string"
        ? res.error
        : JSON.stringify(res.error);
      throw new Error(errMsg);
    }
    if (res.message && res.message.content) {
      return filterResponse(res.message.content);
    }
    throw new Error(JSON.stringify(res));
  };
  const urlBuilder: UrlBuilder = (base, model) => base + "/api/chat";
  const headersBuilder: HeadersBuilder = () => [];
  return handleProvider(
    provider,
    msg,
    hideprompt,
    payloadBuilder,
    responseParser,
    urlBuilder,
    headersBuilder,
  );
}

export function handleGemini(
  provider: ProviderConfig,
  msg: string,
  hideprompt: boolean,
): string {
  if (!provider.authKey) {
    return "ERROR: No auth key configured";
  }

  const payloadBuilder: PayloadBuilder = (model, query) => {
    const payload: Record<string, unknown> = {
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
  };

  const responseParser: ResponseParser = (res) => {
    const r = res as any;
    if (r.candidates && r.candidates[0]?.content?.parts?.[0]?.text) {
      return filterResponse(r.candidates[0].content.parts[0].text);
    }
    if (r.error) {
      throw new Error(
        typeof r.error === "string" ? r.error : JSON.stringify(r.error),
      );
    }
    console.log(JSON.stringify(r));
    throw new Error("Invalid response format");
  };
  const urlBuilder: UrlBuilder = (base, model, key) =>
    `${base}/v1beta/models/${model}:generateContent?key=${key}`;
  const headersBuilder: HeadersBuilder = () => [];
  return handleProvider(
    provider,
    msg,
    hideprompt,
    payloadBuilder,
    responseParser,
    urlBuilder,
    headersBuilder,
  );
}

export function callProvider(msg: string, hideprompt: boolean): string {
  const providerConfig = getProvider(state.api);

  if (!providerConfig) {
    const availableApis = listProviders().join(", ");
    return `Unknown value for 'decai -e api'. Available: ${availableApis}`;
  }

  switch (providerConfig.apiStyle) {
    case "openai":
      return handleOpenAI(providerConfig, msg, hideprompt);
    case "anthropic":
      return handleAnthropic(providerConfig, msg, hideprompt);
    case "ollama":
      return handleOllama(providerConfig, msg, hideprompt);
    case "gemini":
      return handleGemini(providerConfig, msg, hideprompt);
    default:
      return `Unsupported API style: ${providerConfig.apiStyle}`;
  }
}
