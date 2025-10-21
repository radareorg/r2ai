#ifndef INCLUDE_R2AI_PRIV__H
#define INCLUDE_R2AI_PRIV__H

#include "r2ai.h"

typedef struct {
	const char *name;
	const char *url;
	bool requires_api_key;
	bool uses_anthropic_header;
	bool uses_tags_endpoint;
	bool uses_system_ls;
} R2AIProvider;

R_IPI char *r2ai_get_api_key(RCore *core, const char *provider);
R_IPI const R2AIProvider *r2ai_get_provider(const char *name);
R_IPI const char *r2ai_get_provider_url(RCore *core, const char *provider);
R_IPI RList *r2ai_fetch_available_models(RCore *core, const char *provider);
R_IPI void r2ai_list_providers(RCore *core, RStrBuf *sb);
R_IPI void r2ai_refresh_embeddings(RCorePluginSession *cps);
R_IPI void cmd_r2ai_q(RCorePluginSession *cps, const char *input);

#endif
