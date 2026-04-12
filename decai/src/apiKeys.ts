import { API_KEYS_PATH, DECAI_CONFIG_DIR } from "./constants";
import { providerRegistry } from "./providers";
import { ApiKeyResult } from "./types";
import { ensurePath, fileExists, parseEnvLikeString } from "./utils";

function getProviderEnvMap(): Record<string, string> {
  return Object.fromEntries(
    Object.entries(providerRegistry)
      .filter(([, v]) => v.authKey)
      .map(([k, v]) => [k, v.authKey!]),
  );
}

export function getApiKey(provider: string, envvar: string): ApiKeyResult {
  const keyEnv = r2.cmd("'%" + envvar).trim();
  if (!keyEnv.includes("=") && keyEnv !== "") {
    return [keyEnv.trim(), null, "env"];
  }

  const providerLower = provider.toLowerCase();
  const keysPath = API_KEYS_PATH;

  if (fileExists(keysPath)) {
    const keyFile = r2.cmd("'cat " + keysPath);
    const kv = parseEnvLikeString(keyFile);
    if (providerLower in kv) {
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
  ensurePath(DECAI_CONFIG_DIR, API_KEYS_PATH);
  r2.cmd("'ed " + API_KEYS_PATH);
}

export function listApiKeys(): void {
  Object.entries(getProviderEnvMap()).forEach(([key, env]) => {
    const status = getApiKey(key, env)[2];
    console.log(status, "\t", key);
  });
}

