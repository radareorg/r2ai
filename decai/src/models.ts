import { getProvider, listModels } from "./providers";

export function listModelsFor(api: string): void {
  const providerConfig = getProvider(api);

  if (!providerConfig) {
    console.error(`Unknown provider: ${api}`);
    return;
  }

  try {
    const models = listModels(api);

    if (models) {
      console.log(models);
    }

    if (providerConfig.hardcodedModels) {
      providerConfig.hardcodedModels.forEach((model) => console.log(model));
    }

    if (api === "mistral") {
      console.log("ministral-8b-latest");
    }

    if (!models && !providerConfig.hardcodedModels) {
      console.log(providerConfig.defaultModel);
    }
  } catch (e) {
    const err = e as Error;
    console.error(`Error listing models for ${api}:`, err.message);
    console.log(providerConfig.defaultModel);
  }
}
