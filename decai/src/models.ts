import { state } from "./state";
import { padRight } from "./utils";
import { getApiKey } from "./apiKeys";
import { httpGet } from "./http";
import { providerRegistry, getProvider } from "./providers";

export function listClaudeModels(): string {
  const key = getApiKey("anthropic", "ANTHROPIC_API_KEY");
  if (key[1]) throw new Error(key[1]);

  const headers = ["x-api-key: " + key[0], "anthropic-version: 2023-06-01"];
  const response = httpGet("https://api.anthropic.com/v1/models", headers);

  if (response.data) {
    return response.data.map((model) => model.id).join("\n");
  }
  return "";
}

export function listMistralModels(): string {
  const key = getApiKey("mistral", "MISTRAL_API_KEY");
  if (key[1]) throw new Error(key[1]);

  const headers = ["Authorization: Bearer " + key[0]];
  const response = httpGet("https://api.mistral.ai/v1/models", headers);

  if (!response.data) return "";

  const uniqByName = (arr: typeof response.data) =>
    arr.filter(
      (obj, i, self) => self.findIndex((o) => o.name === obj.name) === i
    );

  return uniqByName(response.data)
    .map((model) =>
      [
        padRight(model.name || model.id, 30),
        padRight("" + (model.max_context_length || ""), 10),
        model.description || "",
      ].join(" ")
    )
    .join("\n");
}

export function listOpenaiModels(): string {
  const key = getApiKey("openai", "OPENAI_API_KEY");
  if (key[1]) throw new Error(key[1]);

  const headers = ["Authorization: Bearer " + key[0]];
  const response = httpGet("https://api.openai.com/v1/models", headers);

  if (response.data) {
    return response.data.map((model) => model.id).join("\n");
  }
  return "";
}

export function listOllamaModels(): string {
  const base = state.baseurl || state.host + ":" + state.port;
  const cmd = `curl -s ${base}/api/tags`;
  const res = r2.syscmds(cmd);

  try {
    const parsed = JSON.parse(res);
    if (parsed.models) {
      return parsed.models.map((model: { name: string }) => model.name).join("\n");
    }
    return "";
  } catch (e) {
    console.error(e);
    console.log(res);
    return "error invalid response";
  }
}

export function listOllamaCloudModels(): string {
  const key = getApiKey("ollama", "OLLAMA_API_KEY");
  if (key[1]) throw new Error(key[1]);

  const headers = ["Authorization: Bearer " + key[0]];
  const response = httpGet("https://ollama.com/v1/models", headers);

  if (response.data) {
    return response.data.map((model) => model.id).join("\n");
  }
  return "";
}

export function listModelsFor(api: string): void {
  const providerConfig = getProvider(api);

  if (!providerConfig) {
    console.error(`Unknown provider: ${api}`);
    return;
  }

  try {
    switch (api) {
      case "ollama":
      case "openapi":
        console.log(listOllamaModels());
        break;
      case "lmstudio":
      case "openai":
        console.log(listOpenaiModels());
        break;
      case "claude":
      case "anthropic":
        console.log(listClaudeModels());
        if (providerConfig.hardcodedModels) {
          providerConfig.hardcodedModels.forEach((model) => console.log(model));
        }
        break;
      case "mistral":
        console.log(listMistralModels());
        console.log("codestral-latest");
        break;
      case "ollamacloud":
        console.log(listOllamaCloudModels());
        break;
      default:
        if (providerConfig.hardcodedModels) {
          console.log(providerConfig.hardcodedModels.join("\n"));
        } else {
          console.log(providerConfig.defaultModel);
        }
        break;
    }
  } catch (e) {
    const err = e as Error;
    console.error(`Error listing models for ${api}:`, err.message);
    console.log(providerConfig.defaultModel);
  }
}
