/* Copyright r2ai - 2023-2026 - pancake */

#define R_LOG_ORIGIN "llm"

#include "r2ai.h"
#include "r2ai_priv.h"
#include <string.h>

static const R2AIProvider r2ai_providers[] = {
	{ "openai", "https://api.openai.com/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "gemini", "https://generativelanguage.googleapis.com/v1beta", R2AI_API_GEMINI, true, false },
	{ "anthropic", "https://api.anthropic.com/v1", R2AI_API_ANTHROPIC, true, false },
	{ "claude", "https://api.anthropic.com/v1", R2AI_API_ANTHROPIC, true, false },
	{ "ollama", "http://localhost:11434/v1", R2AI_API_OLLAMA, false, true },
	{ "ollamacloud", "https://ollama.com/api", R2AI_API_OLLAMA, true, true },
	{ "openapi", "http://127.0.0.1:11434", R2AI_API_OPENAI_COMPATIBLE, false, false },
	{ "opencode", "https://opencode.ai/zen/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "zen", "https://opencode.ai/zen/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "xai", "https://api.x.ai/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "openrouter", "https://openrouter.ai/api/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "groq", "https://api.groq.com/openai/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "mistral", "https://api.mistral.ai/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "lmstudio", "http://127.0.0.1:1234/v1", R2AI_API_OPENAI_COMPATIBLE, false, true },
	{ "deepseek", "https://api.deepseek.com/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "vertex", NULL, R2AI_API_VERTEX_GEMINI, false, false },
	{ "vertex-anthropic", NULL, R2AI_API_VERTEX_ANTHROPIC, false, false },
	{ NULL, NULL, R2AI_API_OPENAI_COMPATIBLE, false, false } // sentinel
};

R_IPI const R2AIProvider *r2ai_get_provider(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return NULL;
	}
	for (int i = 0; r2ai_providers[i].name; i++) {
		if (!strcmp (name, r2ai_providers[i].name)) {
			return &r2ai_providers[i];
		}
	}
	return NULL;
}

static bool is_vertex(const R2AIProvider *p) {
	return p->api_type == R2AI_API_VERTEX_GEMINI || p->api_type == R2AI_API_VERTEX_ANTHROPIC;
}

R_IPI R2AI_ChatResponse *r2ai_send(RCorePluginSession *cps, const R2AIProvider *p, R2AIArgs args) {
	switch (p->api_type) {
	case R2AI_API_ANTHROPIC:
		return r2ai_anthropic (cps, args);
	case R2AI_API_GEMINI:
		return r2ai_gemini (cps, args);
	case R2AI_API_VERTEX_GEMINI:
		return r2ai_vertex_gemini (cps, args);
	case R2AI_API_VERTEX_ANTHROPIC:
		return r2ai_vertex_anthropic (cps, args);
	default:
		return r2ai_openai (cps, args);
	}
}

static bool is_generate_api(RCore *core) {
	const char *apitype = r_config_get (core->config, "r2ai.apitype");
	return R_STR_ISNOTEMPTY (apitype) && !strcmp (apitype, "generate");
}

static bool use_rawtools(RCore *core, const R2AIProvider *provider, const R2AIArgs *args) {
	if (!args || !args->tools || r_list_empty (args->tools)) {
		return false;
	}
	if (r_config_get_b (core->config, "r2ai.auto.raw")) {
		return true;
	}
	return provider && provider->api_type == R2AI_API_OLLAMA && is_generate_api (core);
}

// the given system prompt, or r2ai.system when it is empty
R_IPI const char *r2ai_system_prompt(RCore *core, const char *sysp) {
	return R_STR_ISNOTEMPTY (sysp)? sysp: r_config_get (core->config, "r2ai.system");
}

R_IPI R2AI_ChatResponse *r2ai_llmcall(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;
	char *owned_model = NULL;
	char *owned_provider = NULL;
	char *owned_system_prompt = NULL;
	char *api_key = NULL;
	R2AI_ChatResponse *res = NULL;

	const char *provider = args.provider? args.provider: r_config_get (core->config, "r2ai.api");
	if (!provider) {
		provider = "gemini";
	}
	R2AI_State *state = cps->data;
	if (!args.model) {
		const char *config_model = r_config_get (core->config, "r2ai.model");
		owned_model = strdup (config_model? config_model: "");
		args.model = owned_model;
	}
	if (!args.provider) {
		owned_provider = strdup (provider);
		args.provider = owned_provider;
	}

	if (!args.max_tokens) {
		args.max_tokens = r_config_get_i (core->config, "r2ai.max_tokens");
	}
	if (!args.temperature) {
		const char *configtemp = r_config_get (core->config, "r2ai.temperature");
		args.temperature = configtemp? atof (configtemp): 0;
	}

	const R2AIProvider *prov = r2ai_get_provider (provider);
	if (!prov) {
		R_LOG_ERROR ("Unknown provider: %s", provider);
		goto cleanup;
	}

	if (is_vertex (prov)) {
		const char *vtoken = r2ai_vertex_get_token (state);
		if (!vtoken) {
			goto cleanup;
		}
		args.api_key = vtoken;
	} else if (prov->requires_api_key) {
		api_key = r2ai_apikeys_get (provider);
		if (api_key) {
			args.api_key = api_key;
		}
	}
	// Make sure we have an API key before proceeding
	if (prov->requires_api_key && R_STR_ISEMPTY (args.api_key)) {
		R_LOG_ERROR ("No API key found for the %s provider. Use r2ai -K", provider);
		goto cleanup;
	}

	args.system_prompt = r2ai_system_prompt (core, args.system_prompt);
	int context_pullback = -1;
	if (use_rawtools (core, prov, &args)) {
		res = r2ai_rawtools_llmcall (cps, prov, args);
		goto finish;
	}

	owned_system_prompt = r2ai_claw_system_prompt (args.system_prompt);
	args.system_prompt = owned_system_prompt;
	if (!args.messages) {
		args.messages = r2ai_msgs_new ();
	}
	if (args.input && args.messages && r_list_empty (args.messages)) {
		R2AI_Message msg = { .role = "user", .content = (char *)args.input };
		r2ai_msgs_add (args.messages, &msg);
	}
	// context and user message
	if (args.input && r_config_get_b (core->config, "r2ai.data")) {
		const int K = r_config_get_i (core->config, "r2ai.data.nth");
		if (!state->db) {
			state->db = r_vdb_new (R2AI_DEFAULT_VECTORS);
			r2ai_refresh_embeddings (cps);
		}
		RStrBuf *sb = r_strbuf_new ("");
		r_strbuf_appendf (sb, "\n ## Query\n\n%s\n ## Context\n", args.input);
		RVdbResultSet *rs = r_vdb_query (state->db, args.input, K);
		if (rs) {
			int i;
			for (i = 0; i < rs->size; i++) {
				RVdbResult *r = &rs->results[i];
				KDNode *n = r->node;
				r_strbuf_appendf (sb, "- %s.\n", n->text);
			}
			r_vdb_result_free (rs);
		}
		char *m = r_strbuf_drain (sb);
		int last = r_list_length (args.messages) - 1;
		R2AI_Message *last_msg = (last >= 0)? r_list_get_n (args.messages, last): NULL;
		if (last_msg && last_msg->role && !strcmp (last_msg->role, "user")) {
			free ((char *)last_msg->content);
			last_msg->content = m;
			context_pullback = last;
		} else {
			R2AI_Message msg = { .role = "user", .content = m };
			context_pullback = r_list_length (args.messages);
			r2ai_msgs_add (args.messages, &msg);
			free (m);
		}
	}

	args.thinking_tokens = r_config_get_i (core->config, "r2ai.thinking_tokens");

	res = r2ai_send (cps, prov, args);
finish:
	if (context_pullback != -1) {
		R2AI_Message *msg = r_list_get_n (args.messages, context_pullback);
		free ((char *)msg->content);
		msg->content = strdup (args.input);
	}
	if (*args.error) {
		R_LOG_ERROR ("%s", *args.error);
		free (*args.error);
		*args.error = NULL;
	}

cleanup:
	free (api_key);
	free (owned_model);
	free (owned_provider);
	free (owned_system_prompt);
	return res;
}

static char *provider_api_url(const char *host, const char *api_root, bool preserve_root) {
	char *url = r_str_startswith (host, "http")? strdup (host): r_str_newf ("http://%s", host);
	if (!url) {
		return NULL;
	}
	r_str_trim (url);
	size_t len = strlen (url);
	while (len > 0 && url[len - 1] == '/') {
		url[--len] = 0;
	}
	const bool has_root = r_str_endswith (url, "/v1") || r_str_endswith (url, "/api");
	if (has_root && (preserve_root || r_str_endswith (url, api_root))) {
		return url;
	}
	if (has_root) {
		url[len - 3] = 0;
	}
	char *res = r_str_newf ("%s%s", url, api_root);
	free (url);
	return res;
}

R_IPI char *r2ai_get_provider_url(RCore *core, const char *provider) {
	const R2AIProvider *p = r2ai_get_provider (provider);
	if (!p) {
		return NULL;
	}

	if (is_vertex (p)) {
		return NULL;
	}

	const bool is_ollama = p->api_type == R2AI_API_OLLAMA;
	const bool use_generate = is_ollama && is_generate_api (core);

	if (p->supports_custom_baseurl) {
		const char *host = r_config_get (core->config, "r2ai.baseurl");
		if (R_STR_ISNOTEMPTY (host)) {
			const char *api_root = use_generate? "/api": "/v1";
			return provider_api_url (host, api_root, is_ollama && !use_generate);
		}
	}
	if (use_generate) {
		return provider_api_url (p->url, "/api", false);
	}

	return p->url? strdup (p->url): NULL;
}
R_IPI RList *r2ai_fetch_available_models(RCore *core, const char *provider) {
	if (!provider) {
		return NULL;
	}
	const R2AIProvider *p = r2ai_get_provider (provider);
	if (!p) {
		return NULL;
	}
	if (is_vertex (p)) {
		R_LOG_ERROR ("Model listing is not supported for Vertex AI providers");
		return NULL;
	}
	char *purl = r2ai_get_provider_url (core, provider);
	if (!purl) {
		return NULL;
	}
	const bool gemini = p->api_type == R2AI_API_GEMINI;
	const bool usetags = p->api_type == R2AI_API_OLLAMA && r_str_endswith (purl, "/api");
	char *api_key = p->requires_api_key? r2ai_apikeys_get (provider): NULL;
	if (gemini && !api_key) {
		free (purl);
		return NULL;
	}
	char *models_url = r_str_newf ("%s/%s", purl, usetags? "tags": "models");
	char *auth_header = NULL;
	const char *headers[4] = { "Content-Type: application/json", NULL, NULL, NULL };
	if (api_key) {
		if (p->api_type == R2AI_API_ANTHROPIC) {
			auth_header = r_str_newf ("x-api-key: %s", api_key);
			headers[2] = "anthropic-version: 2023-06-01";
		} else if (gemini) {
			auth_header = r_str_newf ("x-goog-api-key: %s", api_key);
		} else {
			auth_header = r_str_newf ("Authorization: Bearer %s", api_key);
		}
		headers[1] = auth_header;
	}
	R_LOG_DEBUG ("GET %s", models_url);
	int code = 0;
	char *response = r2ai_http_get (core, models_url, headers, &code, NULL);
	free (auth_header);
	free (models_url);
	free (api_key);
	free (purl);

	if (!response || code != 200) {
		R_LOG_DEBUG ("Failed to fetch models from %s (code: %d)", provider, code);
		free (response);
		return NULL;
	}

	RList *models = r_list_newf (free);
	RJson *json = r_json_parse (response);
	const RJson *data = json? r_json_get (json, (gemini || usetags)? "models": "data"): NULL;
	const char *key = gemini? "name": usetags? "model": "id";
	const RJson *item;
	for (item = (data && data->type == R_JSON_ARRAY)? data->children.first: NULL; item; item = item->next) {
		const char *id = r_json_get_str (item, key);
		if (R_STR_ISEMPTY (id)) {
			continue;
		}
		if (gemini) {
			// "models/gemini-1.5-flash" -> "gemini-1.5-flash", skipping non gemini models
			const char *slash = strrchr (id, '/');
			id = slash? slash + 1: id;
			if (!strstr (id, "gemini")) {
				continue;
			}
		}
		r_list_append (models, strdup (id));
	}
	r_json_free (json);
	free (response);
	return models;
}

R_IPI void r2ai_list_providers(RCore *core, RStrBuf *sb) {
	for (size_t i = 0; r2ai_providers[i].name; i++) {
		if (sb) {
			if (i > 0) {
				r_strbuf_append (sb, ", ");
			}
			r_strbuf_append (sb, r2ai_providers[i].name);
		} else {
			r_cons_println (core->cons, r2ai_providers[i].name);
		}
	}
}

R_IPI void r2ai_refresh_embeddings(RCorePluginSession *cps) {
	R2AI_State *state = cps->data;
	r_vdb_free (state->db);
	state->db = r_vdb_new (R2AI_DEFAULT_VECTORS);
	const char *path = r_config_get (cps->core->config, "r2ai.data.path");
	RList *files = r_sys_dir (path);
	if (r_list_empty (files)) {
		R_LOG_WARN ("Cannot find any file in r2ai.data.path");
	}
	RListIter *iter, *iter2;
	char *file, *line;
	r_list_foreach (files, iter, file) {
		if (!r_str_endswith (file, ".txt")) {
			continue;
		}
		R_LOG_DEBUG ("Index %s", file);
		char *filepath = r_file_new (path, file, NULL);
		char *text = r_file_slurp (filepath, NULL);
		free (filepath);
		if (!text) {
			continue;
		}
		RList *lines = r_str_split_list (text, "\n", -1);
		r_list_foreach (lines, iter2, line) {
			if (*r_str_trim_head_ro (line)) {
				r_vdb_insert (state->db, line);
			}
		}
		r_list_free (lines);
		free (text);
	}
	r_list_free (files);
}
