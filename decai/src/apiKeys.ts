import { ApiKeyResult } from "./types";
import { fileExists, parseEnvLikeString } from "./utils";

const PROVIDER_ENV_MAP: Record<string, string> = {
  mistral: "MISTRAL_API_KEY",
  anthropic: "ANTHROPIC_API_KEY",
  huggingface: "HUGGINGFACE_API_KEY",
  openai: "OPENAI_API_KEY",
  gemini: "GEMINI_API_KEY",
  deepseek: "DEEPSEEK_API_KEY",
  xai: "XAI_API_KEY",
  ollama: "OLLAMA_API_KEY",
  ollamacloud: "OLLAMA_API_KEY",
};

export function getApiKey(provider: string, envvar: string): ApiKeyResult {
  const keyEnv = r2.cmd("'%" + envvar).trim();
  if (keyEnv.indexOf("=") === -1 && keyEnv !== "") {
    return [keyEnv.trim(), null, "env"];
  }

  const providerLower = provider.toLowerCase();
  const keysPath = "~/.config/r2ai/apikeys.txt";

  if (fileExists(keysPath)) {
    const keyFile = r2.cmd("'cat " + keysPath);
    const kv = parseEnvLikeString(keyFile);
    if (Object.keys(kv).indexOf(providerLower) !== -1) {
      return [kv[providerLower], null, "txt"];
    }
  }

  const keyPath = "~/.r2ai." + providerLower + "-key";
  if (fileExists(keyPath)) {
    const keyFile = r2.cmd("'cat " + keyPath);
    return keyFile === ""
      ? [null, "Cannot read " + keyPath, "no"]
      : [keyFile.trim(), null, "file"];
  }

  return [null, "Not available", "nope"];
}

export function editApiKeys(): void {
  r2.cmd("'ed ~/.config/r2ai/apikeys.txt");
}

export function listApiKeys(): void {
  Object.entries(PROVIDER_ENV_MAP).forEach(([key, env]) => {
    const status = getApiKey(key, env)[2];
    console.log(status, "\t", key);
  });
}

export function getProviderEnvVar(provider: string): string {
  return PROVIDER_ENV_MAP[provider.toLowerCase()] || "";
}
