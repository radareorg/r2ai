#ifndef INCLUDE_R2AI_PRIV__H
#define INCLUDE_R2AI_PRIV__H

#include "r2ai.h"

typedef enum {
	R2AI_API_OPENAI_COMPATIBLE,
	R2AI_API_ANTHROPIC,
	R2AI_API_GEMINI,
	R2AI_API_OLLAMA
} R2AI_API_Type;

typedef struct {
	const char *name;
	const char *url;
	R2AI_API_Type api_type;
	bool requires_api_key;
	bool supports_custom_baseurl;
} R2AIProvider;

R_API void cmd_r2ai(RCorePluginSession *cps, const char *input);
R_IPI char *r2ai_get_api_key(RCore *core, const char *provider);
R_IPI const R2AIProvider *r2ai_get_provider(const char *name);
R_IPI const char *r2ai_get_provider_url(RCore *core, const char *provider);
R_IPI RList *r2ai_fetch_available_models(RCore *core, const char *provider);
R_IPI void r2ai_list_providers(RCore *core, RStrBuf *sb);
R_IPI void r2ai_refresh_embeddings(RCorePluginSession *cps);
R_API char *r2ai_apikeys_path(bool *exists);
R_API void r2ai_apikeys_edit(RCorePluginSession *cps);
R_API char *r2ai_apikeys_get(const char *provider);

#endif
