#define R_LOG_ORIGIN "llm"

#include "r2ai.h"
#include "r2ai_priv.h"
#include <string.h>

static const R2AIProvider r2ai_providers[] = {
	{ "openai", "https://api.openai.com/v1", true, false, false, false },
	{ "gemini", "https://generativelanguage.googleapis.com/v1beta/openai", true, false, false, false },
	{ "anthropic", "https://api.anthropic.com/v1", true, true, false, false },
	{ "ollama", "http://localhost:11434/api", false, false, true, true },
	{ "openapi", "http://127.0.0.1:11434", false, false, false, false },
	{ "xai", "https://api.x.ai/v1", true, false, false, false },
	{ "openrouter", "https://openrouter.ai/api/v1", true, false, false, false },
	{ "groq", "https://api.groq.com/openai/v1", true, false, false, false },
	{ "mistral", "https://api.mistral.ai/v1", true, false, false, false },
	{ NULL, NULL, false, false, false, false } // sentinel
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

// Forward declaration for rawtools
R_API R2AI_ChatResponse *r2ai_rawtools_llmcall(RCorePluginSession *cps, R2AIArgs args);

R_IPI R2AI_ChatResponse *r2ai_llmcall(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;

	// Check if rawtools mode is enabled
	bool rawtools_enabled = r_config_get_b (core->config, "r2ai.rawtools");
	if (rawtools_enabled) {
		return r2ai_rawtools_llmcall (cps, args);
	}

	R2AI_State *state = cps->data;
	R2AI_ChatResponse *res = NULL;
	const char *provider = args.provider? args.provider: r_config_get (core->config, "r2ai.api");
	if (!provider) {
		provider = "gemini";
	}
	if (!args.model) {
		const char *config_model = r_config_get (core->config, "r2ai.model");
		args.model = strdup (config_model? config_model: "");
	}
	if (!args.provider) {
		args.provider = strdup (provider);
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
		return NULL;
	}

	char *api_key = NULL;
	if (prov->requires_api_key) {
		api_key = r2ai_get_api_key (core, provider);
		if (api_key) {
			args.api_key = api_key;
		}
	}
	// Make sure we have an API key before proceeding
	if (prov->requires_api_key) {
		if (R_STR_ISEMPTY (args.api_key)) {
			char *Provider = strdup (provider);
			r_str_case (Provider, true);
			R_LOG_ERROR ("No API key found for %s provider. Please set one with: r2ai "
				"%s_API_KEY=YOUR_KEY",
				provider, Provider);
			free (Provider);
			return NULL;
		}
	}

	// Set system_prompt from config if it's not already set
	if (!args.system_prompt) {
		args.system_prompt = r_config_get (core->config, "r2ai.system");
	}
	if (!args.messages) {
		args.messages = r2ai_msgs_new ();
	}
	int context_pullback = -1;
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
		R2AI_Message msg = { .role = "user", .content = m };
		context_pullback = r_list_length (args.messages->messages);
		r2ai_msgs_add (args.messages, &msg);
		free (m);
		// TODO: we can save the msg without context
	}

	// Add the rest of the messages one by one
	if (!args.messages && args.input) {
		R2AI_Message msg = { .role = "user", .content = args.input };
		args.messages = r2ai_msgs_new ();
		r2ai_msgs_add (args.messages, &msg);
	}

	args.thinking_tokens = r_config_get_i (core->config, "r2ai.thinking_tokens");

	const R2AIProvider *p = r2ai_get_provider (provider);
	if (p && p->uses_anthropic_header) {
		res = r2ai_anthropic (cps, args);
	} else {
		res = r2ai_openai (cps, args);
	}
	if (context_pullback != -1) {
		R2AI_Message *msg = r_list_get_n (args.messages->messages, context_pullback);
		free ((char *)msg->content);
		msg->content = strdup (args.input);
	}
	if (*args.error) {
		R_LOG_ERROR ("%s", *args.error);
		free (*args.error);
		*args.error = NULL;
	}

	return res;
}

/* Return a malloc'd API key read from the environment or from ~/.r2ai.<provider>-key
 * Caller is responsible for freeing the returned string (or NULL if not found). */
R_IPI char *r2ai_get_api_key(RCore *core, const char *provider) {
	(void)core;
	char *api_key = NULL;
	char *api_key_env = r_str_newf ("%s_API_KEY", provider);
	r_str_case (api_key_env, true);
	char *s = r_sys_getenv (api_key_env);
	free (api_key_env);
	if (R_STR_ISNOTEMPTY (s)) {
		api_key = s;
	} else {
		free (s);
		char *api_key_filename = r_str_newf ("~/.r2ai.%s-key", provider);
		char *absolute_apikey = r_file_abspath (api_key_filename);
		if (r_file_exists (absolute_apikey)) {
			api_key = r_file_slurp (absolute_apikey, NULL);
			if (api_key) {
				r_str_trim (api_key);
			}
		}
		free (api_key_filename);
		free (absolute_apikey);
	}
	return api_key;
}

R_IPI const char *r2ai_get_provider_url(RCore *core, const char *provider) {
	const R2AIProvider *p = r2ai_get_provider (provider);
	if (!p) {
		return NULL;
	}

	// Handle providers that support custom baseurl
	if (!strcmp (provider, "openai") || !strcmp (provider, "ollama")) {
		const char *host = r_config_get (core->config, "r2ai.baseurl");
		if (R_STR_ISNOTEMPTY (host)) {
			if (r_str_startswith (host, "http")) {
				if (!strcmp (provider, "openai")) {
					return r_str_newf ("%s/v1", host);
				} else {
					return r_str_newf ("%s/api", host);
				}
			}
			if (!strcmp (provider, "openai")) {
				return r_str_newf ("http://%s/v1", host);
			} else {
				return r_str_newf ("http://%s/api", host);
			}
		}
	}

	return p->url;
}
R_IPI RList *r2ai_fetch_available_models(RCore *core, const char *provider) {
	const char *purl = r2ai_get_provider_url (core, provider);
	if (!purl) {
		return NULL;
	}

	// Create models endpoint URL
	char *models_url = NULL;
	const R2AIProvider *prov = r2ai_get_provider (provider);
	if (prov && prov->uses_tags_endpoint) {
		models_url = r_str_newf ("%s/tags", purl);
	} else {
		models_url = r_str_newf ("%s/models", purl);
	}
	if (!models_url) {
		return NULL;
	}

	// Get API key for authentication (except for providers that don't require it)
	char *api_key = NULL;
	const R2AIProvider *p = r2ai_get_provider (provider);
	if (p && p->requires_api_key) {
		// Consolidated helper to fetch the API key from env or file
		api_key = r2ai_get_api_key (core, provider);
	}

	int code = 0;
	char *response = NULL;
	if (api_key) {
		const char *headers[4] = { "Content-Type: application/json", NULL, NULL, NULL };
		char *auth_header = NULL;
		char *version_header = NULL;

		const R2AIProvider *prov = r2ai_get_provider (provider);
		if (prov && prov->uses_anthropic_header) {
			// Anthropic uses different header format
			auth_header = r_str_newf ("x-api-key: %s", api_key);
			version_header = strdup ("anthropic-version: 2023-06-01");
			headers[1] = auth_header;
			headers[2] = version_header;
		} else {
			// Standard OpenAI-compatible format
			auth_header = r_str_newf ("Authorization: Bearer %s", api_key);
			headers[1] = auth_header;
		}

		// Make HTTP GET request
		R_LOG_DEBUG ("GET %s Headers: %s", models_url, headers);
		response = r2ai_http_get (core, models_url, headers, &code, NULL);
		free (auth_header);
		free (version_header);
		free (api_key);
	} else {
		// We have no headers
		R_LOG_DEBUG ("GET %s", models_url);
		response = r2ai_http_get (core, models_url, NULL, &code, NULL);
	}

	free (models_url);

	if (!response || code != 200) {
		R_LOG_DEBUG ("Failed to fetch models from %s (code: %d)", provider, code);
		free (response);
		return NULL;
	}

	// Parse JSON response
	RList *models = r_list_newf (free);
	if (!models) {
		free (response);
		return NULL;
	}

	RJson *json = r_json_parse (response);
	if (json) {
		const RJson *data;
		const R2AIProvider *prov = r2ai_get_provider (provider);
		if (prov && prov->uses_tags_endpoint) {
			data = r_json_get (json, "models");
		} else {
			data = r_json_get (json, "data");
		}

		if (data && data->type == R_JSON_ARRAY) {
			const RJson *model_item = data->children.first;
			while (model_item) {
				const RJson *id;
				if (prov && prov->uses_tags_endpoint) {
					id = r_json_get (model_item, "model");
				} else {
					id = r_json_get (model_item, "id");
				}
				if (id && id->type == R_JSON_STRING && R_STR_ISNOTEMPTY (id->str_value)) {
					R_LOG_DEBUG ("Model: %s", id->str_value);
					r_list_append (models, strdup (id->str_value));
				}
				model_item = model_item->next;
			}
		}
		r_json_free (json);
	}

	free (response);
	return models;
}

R_IPI void r2ai_list_providers(RCore *core, RStrBuf *sb) {
	size_t i;
	for (i = 0; r2ai_providers[i].name; i++) {
		if (sb) {
			if (i > 0) {
				r_strbuf_append (sb, ", ");
			}
			r_strbuf_append (sb, r2ai_providers[i].name);
		} else {
			R2_PRINTLN (r2ai_providers[i].name);
		}
	}
}

R_IPI void r2ai_refresh_embeddings(RCorePluginSession *cps) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	RListIter *iter, *iter2;
	char *line;
	char *file;
	// refresh embeddings database
	r_vdb_free (state->db);
	state->db = r_vdb_new (R2AI_DEFAULT_VECTORS);
	// enumerate .txt files in directory
	const char *path = r_config_get (core->config, "r2ai.data.path");
	RList *files = r_sys_dir (path);
	if (r_list_empty (files)) {
		R_LOG_WARN ("Cannot find any file in r2ai.data.path");
	}
	r_list_foreach (files, iter, file) {
		if (!r_str_endswith (file, ".txt")) {
			continue;
		}
		R_LOG_DEBUG ("Index %s", file);
		char *filepath = r_file_new (path, file, NULL);
		char *text = r_file_slurp (filepath, NULL);
		if (text) {
			RList *lines = r_str_split_list (text, "\n", -1);
			r_list_foreach (lines, iter2, line) {
				if (r_str_trim_head_ro (line)[0] == 0) {
					continue;
				}
				r_vdb_insert (state->db, line);
				R_LOG_DEBUG ("Insert %s", line);
			}
			r_list_free (lines);
		}
		free (filepath);
	}
	r_list_free (files);
}
