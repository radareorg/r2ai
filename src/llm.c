#define R_LOG_ORIGIN "llm"

#include "r2ai.h"
#include "r2ai_priv.h"
#include <string.h>

static const R2AIProvider r2ai_providers[] = {
	{ "openai", "https://api.openai.com/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "gemini", "https://generativelanguage.googleapis.com/v1beta", R2AI_API_GEMINI, true, false },
	{ "anthropic", "https://api.anthropic.com/v1", R2AI_API_ANTHROPIC, true, false },
	{ "ollama", "http://localhost:11434/api", R2AI_API_OLLAMA, false, true },
	{ "openapi", "http://127.0.0.1:11434", R2AI_API_OPENAI_COMPATIBLE, false, false },
	{ "xai", "https://api.x.ai/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "openrouter", "https://openrouter.ai/api/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "groq", "https://api.groq.com/openai/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "mistral", "https://api.mistral.ai/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
	{ "deepseek", "https://api.deepseek.com/v1", R2AI_API_OPENAI_COMPATIBLE, true, true },
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

// Forward declaration for rawtools
R_IPI R2AI_ChatResponse *r2ai_llmcall(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;

	// Check if rawtools mode is enabled
	bool rawtools_enabled = r_config_get_b (core->config, "r2ai.auto.raw");
	const char *provider = args.provider? args.provider: r_config_get (core->config, "r2ai.api");
	if (!provider) {
		provider = "gemini";
	}
	if (rawtools_enabled && args.tools && r_list_length (args.tools) > 0) {
		return r2ai_rawtools_llmcall (cps, args);
	}
	R2AI_State *state = cps->data;
	R2AI_ChatResponse *res = NULL;
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
		api_key = r2ai_apikeys_get (provider);
		if (api_key) {
			args.api_key = api_key;
		}
	}
	// Make sure we have an API key before proceeding
	if (prov->requires_api_key) {
		if (R_STR_ISEMPTY (args.api_key)) {
			char *Provider = strdup (provider);
			r_str_case (Provider, true);
			R_LOG_ERROR ("No API key found for the %s provider. Use r2ai -K", provider);
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
		context_pullback = r_list_length (args.messages);
		r2ai_msgs_add (args.messages, &msg);
		free (m);
		// TODO: we can save the msg without context
	}

	// Add the rest of the messages one by one
	if (!args.messages && args.input) {
		R2AI_Message msg = { .role = "user", .content = (char *)args.input };
		args.messages = r2ai_msgs_new ();
		r2ai_msgs_add (args.messages, &msg);
	}

	args.thinking_tokens = r_config_get_i (core->config, "r2ai.thinking_tokens");

	const R2AIProvider *p = r2ai_get_provider (provider);
	if (!p) {
		return NULL;
	}

	switch (p->api_type) {
	case R2AI_API_ANTHROPIC:
		res = r2ai_anthropic (cps, args);
		break;
	case R2AI_API_GEMINI:
		res = r2ai_gemini (cps, args);
		break;
	case R2AI_API_OPENAI_COMPATIBLE:
	case R2AI_API_OLLAMA:
	default:
		res = r2ai_openai (cps, args);
		break;
	}
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

	return res;
}

R_IPI const char *r2ai_get_provider_url(RCore *core, const char *provider) {
	const R2AIProvider *p = r2ai_get_provider (provider);
	if (!p) {
		return NULL;
	}

	// Handle providers that support custom baseurl
	if (p->supports_custom_baseurl) {
		const char *host = r_config_get (core->config, "r2ai.baseurl");
		if (R_STR_ISNOTEMPTY (host)) {
			if (r_str_startswith (host, "http")) {
				if (p->api_type == R2AI_API_OPENAI_COMPATIBLE) {
					return r_str_newf ("%s/v1", host);
				}
				return r_str_newf ("%s/api", host);
			}
			if (p->api_type == R2AI_API_OPENAI_COMPATIBLE) {
				return r_str_newf ("http://%s/v1", host);
			}
			return r_str_newf ("http://%s/api", host);
		}
	}

	return p->url;
}
R_IPI RList *r2ai_fetch_available_models(RCore *core, const char *provider) {
	if (!provider) {
		return NULL;
	}
	const char *purl = r2ai_get_provider_url (core, provider);
	if (!purl) {
		return NULL;
	}

	// Get API key for authentication (except for providers that don't require it)
	char *api_key = NULL;
	const R2AIProvider *p = r2ai_get_provider (provider);
	if (p && p->requires_api_key) {
		// Consolidated helper to fetch the API key from env or file
		api_key = r2ai_apikeys_get (provider);
	}

	char *models_url = NULL;
	int code = 0;
	char *response = NULL;

	// Special handling for Gemini
	if (!strcmp (provider, "gemini")) {
		if (!api_key) {
			return NULL;
		}
		models_url = r_str_newf ("%s/models?key=%s", purl, api_key);
		const char *headers[2] = { "Content-Type: application/json", NULL };
		R_LOG_DEBUG ("GET %s", models_url);
		response = r2ai_http_get (core, models_url, headers, &code, NULL);
	} else {
		// Create models endpoint URL
		const R2AIProvider *prov = r2ai_get_provider (provider);
		const bool usetags = (prov && prov->api_type == R2AI_API_OLLAMA);
		models_url = r_str_newf ("%s/%s", purl, usetags? "tags": "models");

		if (api_key) {
			const char *headers[4] = { "Content-Type: application/json", NULL, NULL, NULL };
			char *auth_header = NULL;
			char *version_header = NULL;

			const R2AIProvider *prov = r2ai_get_provider (provider);
			if (prov && prov->api_type == R2AI_API_ANTHROPIC) {
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
		} else {
			// We have no headers
			R_LOG_DEBUG ("GET %s", models_url);
			response = r2ai_http_get (core, models_url, NULL, &code, NULL);
		}
	}

	free (models_url);
	free (api_key);

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
		const RJson *data = NULL;

		if (!strcmp (provider, "gemini")) {
			// Gemini has "models" array directly
			data = r_json_get (json, "models");
		} else {
			const R2AIProvider *prov = r2ai_get_provider (provider);
			const bool usetags = (prov && prov->api_type == R2AI_API_OLLAMA);
			data = r_json_get (json, usetags? "models": "data");
		}

		if (data && data->type == R_JSON_ARRAY) {
			const RJson *model_item = data->children.first;
			while (model_item) {
				const RJson *id = NULL;
				char *model_id = NULL;

				if (!strcmp (provider, "gemini")) {
					// Gemini: extract model ID from "name" field (e.g., "models/gemini-1.5-flash" -> "gemini-1.5-flash")
					const RJson *name = r_json_get (model_item, "name");
					if (name && name->type == R_JSON_STRING && R_STR_ISNOTEMPTY (name->str_value)) {
						char *s = strdup (name->str_value);
						RList *parts = r_str_split_list (s, "/", 0);
						if (parts && r_list_length (parts) > 1) {
							model_id = strdup ((char *)r_list_get_n (parts, r_list_length (parts) - 1));
						} else {
							model_id = strdup (name->str_value);
						}
						r_list_free (parts);
						// Only include Gemini models
						if (!strstr (model_id, "gemini")) {
							free (model_id);
							model_id = NULL;
						}
						free (s);
					}
				} else {
					const R2AIProvider *prov = r2ai_get_provider (provider);
					if (prov && prov->api_type == R2AI_API_OLLAMA) {
						id = r_json_get (model_item, "model");
					} else {
						id = r_json_get (model_item, "id");
					}
					if (id && id->type == R_JSON_STRING && R_STR_ISNOTEMPTY (id->str_value)) {
						model_id = strdup (id->str_value);
					}
				}

				if (model_id) {
					R_LOG_DEBUG ("Model: %s", model_id);
					r_list_append (models, model_id);
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
			R_LOG_DEBUG ("Index %s", file);
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
