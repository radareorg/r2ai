/* r2ai - Copyright 2023-2026 pancake, dnakov */

#include "r2ai.h"
#include "r2ai_priv.h"

static const char *json_string(const RJson *json) {
	return (json && json->type == R_JSON_STRING)? json->str_value: NULL;
}

static uint64_t json_integer(const RJson *json) {
	return (json && json->type == R_JSON_INTEGER)? json->num.u_value: 0;
}

typedef enum {
	R2AI_CHAT_OPENAI,
	R2AI_CHAT_OLLAMA,
	R2AI_GENERATE_OLLAMA
} R2AIChatAPI;

static bool is_generate_api(RCore *core) {
	const char *apitype = r_config_get (core->config, "r2ai.apitype");
	if (R_STR_ISEMPTY (apitype)) {
		return false;
	}
	return !strcmp (apitype, "generate");
}

static char *ollama_generate_prompt_from_messages(const RList *msgs, char **system_prompt) {
	if (system_prompt) {
		*system_prompt = NULL;
	}
	if (!msgs || r_list_empty (msgs)) {
		return NULL;
	}

	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}

	RListIter *iter;
	const R2AI_Message *msg;
	r_list_foreach (msgs, iter, msg) {
		const char *role = msg->role? msg->role: "user";
		const char *content = msg->content;
		if (R_STR_ISEMPTY (content)) {
			continue;
		}
		if (!strcmp (role, "system") || !strcmp (role, "developer")) {
			if (system_prompt && !*system_prompt) {
				*system_prompt = strdup (content);
				continue;
			}
		}
		r_strbuf_appendf (sb, "%s: %s\n\n", role, content);
	}

	char *prompt = r_strbuf_drain (sb);
	if (R_STR_ISEMPTY (prompt) && system_prompt && *system_prompt) {
		free (prompt);
		prompt = strdup (*system_prompt);
	}
	return prompt;
}

static void cache_part(RStrBuf *sb, const char *s) {
	const char *v = r_str_get (s);
	r_strbuf_appendf (sb, "%zu:%s\n", strlen (v), v);
}

static char *cache_prefix(const char *provider, const char *model, const char *tools_json, const char *messages_json) {
	RStrBuf *sb = r_strbuf_new ("");
	cache_part (sb, provider);
	cache_part (sb, model);
	cache_part (sb, tools_json);
	const char *messages = r_str_get (messages_json);
	size_t len = strlen (messages);
	if (len > 0 && messages[len - 1] == ']') {
		len--;
	}
	r_strbuf_appendf (sb, "%zu:", len);
	r_strbuf_append_n (sb, messages, len);
	return r_strbuf_drain (sb);
}

static size_t prefix_len(const char *a, const char *b) {
	size_t i = 0;
	while (a[i] && b[i] && a[i] == b[i]) {
		i++;
	}
	return i;
}

static void check_chat_cache(RCorePluginSession *cps, const char *provider, const char *model, const char *tools_json, const char *messages_json) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	if (!state || !r_config_get_b (core->config, "r2ai.cacheck")) {
		return;
	}
	char *prefix = cache_prefix (provider, model, tools_json, messages_json);
	if (state->cache_prefix) {
		const size_t old_len = strlen (state->cache_prefix);
		if (!r_str_startswith (prefix, state->cache_prefix)) {
			const size_t kept = prefix_len (state->cache_prefix, prefix);
			R_LOG_WARN ("Chat cache prefix changed: preserved %zu/%zu bytes from previous request. Keep system prompt, tool catalog, and previous messages append-only to maximize provider cache hits.", kept, old_len);
		} else {
			R_LOG_DEBUG ("Chat cache prefix preserved: %zu bytes", old_len);
		}
		R_FREE (state->cache_prefix);
	}
	state->cache_prefix = prefix;
}

static char *chat_request_json(RCorePluginSession *cps, const R2AIArgs *args, const char *provider, const char *model, const RList *messages, R2AIChatAPI api, bool check_cache) {
	const bool use_generate = api == R2AI_GENERATE_OLLAMA;
	const bool use_ollama = api != R2AI_CHAT_OPENAI;
	const R2AIProvider *provider_info = r2ai_get_provider (provider);
	const bool is_ollama_provider = provider_info && provider_info->api_type == R2AI_API_OLLAMA;
	char *messages_json = NULL;
	char *generate_prompt = NULL;
	char *generate_system = NULL;
	if (use_generate) {
		generate_prompt = ollama_generate_prompt_from_messages (messages, &generate_system);
	} else {
		messages_json = r2ai_msgs_to_json (messages, use_ollama);
	}
	if (!messages_json && !generate_prompt) {
		return NULL;
	}

	char *tools_json = NULL;
	if (args->tools && !r_list_empty (args->tools)) {
		if (use_generate) {
			R_LOG_DEBUG ("Skipping native tool definitions for /api/generate payload");
		} else {
			tools_json = r2ai_tools_to_openai_json (args->tools);
		}
	}

	PJ *pj = pj_new ();
	if (!pj) {
		free (messages_json);
		free (generate_prompt);
		free (generate_system);
		free (tools_json);
		return NULL;
	}
	pj_o (pj);
	pj_ks (pj, "model", model);
	pj_kb (pj, "stream", false);
	if (use_ollama) {
		pj_kb (pj, "think", args->thinking_tokens > 0);
		pj_ko (pj, "options");
		if (args->max_tokens) {
			pj_kn (pj, "num_predict", args->max_tokens);
		}
		if (args->temperature > 0) {
			pj_kd (pj, "temperature", args->temperature);
		}
		pj_end (pj);
	} else if (is_ollama_provider || !strcmp (provider, "mistral")) {
		pj_kn (pj, "max_tokens", args->max_tokens? args->max_tokens: 5128);
	} else {
		pj_kn (pj, "max_completion_tokens", args->max_tokens? args->max_tokens: 5128);
	}
	if (use_generate) {
		pj_ks (pj, "prompt", generate_prompt);
		if (R_STR_ISNOTEMPTY (generate_system)) {
			pj_ks (pj, "system", generate_system);
		}
	} else {
		pj_k (pj, "messages");
		pj_raw (pj, messages_json);
		if (tools_json) {
			pj_k (pj, "tools");
			pj_raw (pj, tools_json);
		}
	}
	pj_end (pj);

	if (!use_generate && check_cache) {
		check_chat_cache (cps, provider, model, tools_json, messages_json);
	}
	free (messages_json);
	free (generate_prompt);
	free (generate_system);
	free (tools_json);
	return pj_drain (pj);
}

static char *chat_api_url(const char *base_url, R2AIChatAPI api) {
	const char *path = api == R2AI_CHAT_OPENAI
		? "/chat/completions"
		: (api == R2AI_GENERATE_OLLAMA? "/generate": "/chat");
	return r_str_newf ("%s%s", base_url, path);
}

static char *ollama_native_base(const char *base_url) {
	if (r_str_endswith (base_url, "/api")) {
		return strdup (base_url);
	}
	if (r_str_endswith (base_url, "/v1")) {
		char *url = strdup (base_url);
		if (!url) {
			return NULL;
		}
		url[strlen (url) - 3] = 0;
		char *res = r_str_newf ("%s/api", url);
		free (url);
		return res;
	}
	return r_str_newf ("%s/api", base_url);
}

static bool allow_ollama_fallback(RCore *core, const char *provider) {
	if (strcmp (provider, "ollama")) {
		return false;
	}
	const char *base_url = r_config_get (core->config, "r2ai.baseurl");
	if (R_STR_ISEMPTY (base_url)) {
		return true;
	}
	char *url = strdup (base_url);
	if (!url) {
		return false;
	}
	r_str_trim (url);
	size_t len = strlen (url);
	while (len > 0 && url[len - 1] == '/') {
		url[--len] = 0;
	}
	const bool explicit_root = r_str_endswith (url, "/v1") || r_str_endswith (url, "/api");
	free (url);
	return !explicit_root;
}

R_IPI R2AI_ChatResponse *r2ai_openai(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;
	const char *provider_name = R_STR_ISNOTEMPTY (args.provider)
		? args.provider
		: r_config_get (core->config, "r2ai.api");
	const char *model_name = R_STR_ISNOTEMPTY (args.model)
		? args.model
		: r_config_get (core->config, "r2ai.model");

	const R2AIProvider *provider_info = r2ai_get_provider (provider_name);
	const bool is_ollama_provider = provider_info && provider_info->api_type == R2AI_API_OLLAMA;
	const bool use_generate = is_ollama_provider && is_generate_api (core);
	char *base_url = r2ai_get_provider_url (core, provider_name);
	if (!base_url) {
		if (args.error) {
			*args.error = strdup ("Failed to resolve provider URL");
		}
		return NULL;
	}
	R2AIChatAPI chat_api = use_generate
		? R2AI_GENERATE_OLLAMA
		: (is_ollama_provider && r_str_endswith (base_url, "/api")? R2AI_CHAT_OLLAMA: R2AI_CHAT_OPENAI);
	// TODO: default model name should depend on api
	model_name = model_name? model_name: "gpt-4o-mini";
	char **error = args.error;
	// create a temp conversation to include the system prompt and the rest of the messages
	RList *temp_msgs = r2ai_msgs_new ();
	if (!temp_msgs) {
		if (error) {
			*error = strdup ("Failed to create temporary messages array");
		}
		free (base_url);
		return NULL;
	}
	R2AI_Message system_msg = {
		.role = "system",
		.content = (char *)args.system_prompt
	};
	// Add system message if available from args.system_prompt
	if (R_STR_ISNOTEMPTY (args.system_prompt)) {
		R_LOG_DEBUG ("Using system prompt: %s", args.system_prompt);
		// if the model name contains "o1" or "o3", it's "developer" role
		if (strstr (model_name, "o1") || strstr (model_name, "o3")) {
			system_msg.role = "developer";
			system_msg.content = (char *)args.system_prompt;
		} else {
			system_msg.role = "system";
			system_msg.content = (char *)args.system_prompt;
		}
		r2ai_msgs_add (temp_msgs, &system_msg);
	} else {
		// Fallback to config if args.system_prompt is not set
		const char *sysprompt = r_config_get (core->config, "r2ai.system");
		if (R_STR_ISNOTEMPTY (sysprompt)) {
			R_LOG_DEBUG ("Using system prompt from config: %s", sysprompt);
			if (strstr (model_name, "o1") || strstr (model_name, "o3")) {
				system_msg.role = "developer";
			} else {
				system_msg.role = "system";
			}
			system_msg.content = (char *)sysprompt;
			r2ai_msgs_add (temp_msgs, &system_msg);
		}
	}
	if (args.messages) {
		RListIter *iter;
		R2AI_Message *msg;
		r_list_foreach (args.messages, iter, msg) {
			r2ai_msgs_add (temp_msgs, msg);
		}
	} else {
		R_LOG_WARN ("No messages");
	}
	// Safely print debug info about first message
	if (temp_msgs && !r_list_empty (temp_msgs) && ((R2AI_Message *)r_list_get_n (temp_msgs, 0))->role) {
		R_LOG_DEBUG ("First message role: %s", ((R2AI_Message *)r_list_get_n (temp_msgs, 0))->role);
	}
	if (error) {
		*error = NULL;
	}

	char *auth_header = NULL;
	const char *headers[] = { "Content-Type: application/json", NULL, NULL };
	if (R_STR_ISNOTEMPTY (args.api_key)) {
		auth_header = r_str_newf ("Authorization: Bearer %s", args.api_key);
		R_LOG_DEBUG ("Auth header: %s", auth_header);
		headers[1] = auth_header;
	}
	if (r_list_empty (temp_msgs)) {
		if (error) {
			*error = strdup ("No messages provided");
		}
		free (auth_header);
		free (base_url);
		r2ai_msgs_free (temp_msgs);
		return NULL;
	}
	R_LOG_DEBUG ("Using input messages: %d messages", r_list_length (temp_msgs));

	char *res = NULL;
	int code = 0;
	char *fallback_base = NULL;
	const char *request_base = base_url;
	bool first_request = true;
	for (;;) {
		char *request_json = chat_request_json (cps, &args, provider_name, model_name, temp_msgs, chat_api, first_request);
		if (!request_json) {
			if (error) {
				*error = strdup ("Failed to create request JSON");
			}
			free (fallback_base);
			free (auth_header);
			free (base_url);
			r2ai_msgs_free (temp_msgs);
			return NULL;
		}
		char *api_url = chat_api_url (request_base, chat_api);
		char *tmpdir = r_file_tmpdir ();
		char *req_path = r_str_newf ("%s" R_SYS_DIR "r2ai_openai_request.json", tmpdir);
		r_file_dump (req_path, (const ut8 *)request_json, strlen (request_json), 0);
		R_LOG_DEBUG ("Full request saved to %s", req_path);
		R_LOG_DEBUG ("LLM API request data: %s", request_json);
		free (req_path);
		free (tmpdir);

		if (r_config_get_b (core->config, "r2ai.debug")) {
			RStrBuf *curl_cmd = r_strbuf_new ("curl -X POST");
			for (int i = 0; headers[i]; i++) {
				r_strbuf_appendf (curl_cmd, " -H \"%s\"", headers[i]);
			}
			r_strbuf_appendf (curl_cmd, " -d '%s' \"%s\"", request_json, api_url);
			eprintf ("Curl command: %s\n", r_strbuf_get (curl_cmd));
			r_strbuf_free (curl_cmd);
		}

		res = r2ai_http_post (core, api_url, headers, request_json, &code, NULL);
		free (request_json);
		free (api_url);
		if (chat_api != R2AI_CHAT_OPENAI || (code != 404 && code != 405) || !allow_ollama_fallback (core, provider_name)) {
			break;
		}
		fallback_base = ollama_native_base (base_url);
		if (!fallback_base) {
			break;
		}
		R_LOG_INFO ("OpenAI-compatible Ollama endpoint unavailable; falling back to /api/chat");
		free (res);
		res = NULL;
		request_base = fallback_base;
		chat_api = R2AI_CHAT_OLLAMA;
		first_request = false;
	}
	free (fallback_base);
	free (base_url);

	if (code != 200) {
		R_LOG_ERROR ("LLM API error %d", code);
		if (res) {
			R_LOG_ERROR ("LLM API error response: %s", res);
		}
		free (auth_header);
		free (res);
		r2ai_msgs_free (temp_msgs);
		return NULL;
	}

	// Save the response for inspection
	char *tmpdir = r_file_tmpdir ();
	char *res_path = r_str_newf ("%s" R_SYS_DIR "r2ai_openai_response.json", tmpdir);
	r_file_dump (res_path, (const ut8 *)res, strlen (res), 0);
	if (r_config_get_b (core->config, "r2ai.debug")) {
		eprintf ("OpenAI API response: %s\n", res);
	}
	free (res_path);
	free (tmpdir);

	// Parse the response into our messages structure

	char *res_copy = strdup (res);
	RJson *jres = r_json_parse (res_copy);
	if (jres) {
		const bool is_native_ollama = chat_api != R2AI_CHAT_OPENAI;
		R2AI_Message *message = R_NEW0 (R2AI_Message);
		R2AI_Usage *usage = R_NEW0 (R2AI_Usage);
		const RJson *usage_json = is_native_ollama? jres: r_json_get (jres, "usage");
		if (usage_json && usage_json->type == R_JSON_OBJECT) {
			usage->prompt_tokens = json_integer (r_json_get (usage_json, is_native_ollama? "prompt_eval_count": "prompt_tokens"));
			usage->completion_tokens = json_integer (r_json_get (usage_json, is_native_ollama? "eval_count": "completion_tokens"));
			usage->total_tokens = is_native_ollama
				? usage->prompt_tokens + usage->completion_tokens
				: json_integer (r_json_get (usage_json, "total_tokens"));
		}

		const RJson *message_json = NULL;
		if (use_generate) {
			const char *content = json_string (r_json_get (jres, "response"));
			const char *thinking = json_string (r_json_get (jres, "thinking"));
			message->role = strdup ("assistant");
			if (content) {
				message->content = strdup (content);
			}
			if (R_STR_ISNOTEMPTY (thinking)) {
				message->reasoning_content = strdup (thinking);
			}
		} else if (is_native_ollama) {
			message_json = r_json_get (jres, "message");
		} else {
			const RJson *choices = r_json_get (jres, "choices");
			if (choices && choices->type == R_JSON_ARRAY) {
				const RJson *choice = r_json_item (choices, 0);
				message_json = choice? r_json_get (choice, "message"): NULL;
			}
		}

		if (message_json) {
			const char *role = json_string (r_json_get (message_json, "role"));
			const char *content = json_string (r_json_get (message_json, "content"));
			const char *reasoning_content = json_string (r_json_get (message_json, "reasoning_content"));
			const char *thinking = json_string (r_json_get (message_json, "thinking"));
			const char *tool_call_id = json_string (r_json_get (message_json, "tool_call_id"));
			const RJson *tool_calls = r_json_get (message_json, "tool_calls");

			message->role = strdup (role? role: "assistant");
			if (content) {
				message->content = strdup (content);
			}
			if (R_STR_ISNOTEMPTY (reasoning_content)) {
				message->reasoning_content = strdup (reasoning_content);
			} else if (R_STR_ISNOTEMPTY (thinking)) {
				message->reasoning_content = strdup (thinking);
			}
			if (R_STR_ISNOTEMPTY (tool_call_id)) {
				message->tool_call_id = strdup (tool_call_id);
			}

			if (tool_calls && tool_calls->type == R_JSON_ARRAY && tool_calls->children.count > 0) {
				message->tool_calls = r_list_newf ((RListFree)r2ai_tool_call_free);
				if (message->tool_calls) {
					size_t i;
					for (i = 0; i < tool_calls->children.count; i++) {
						const RJson *tool_call = r_json_item (tool_calls, i);
						if (!tool_call || tool_call->type != R_JSON_OBJECT) {
							continue;
						}
						const RJson *function = r_json_get (tool_call, "function");
						const RJson *source = (function && function->type == R_JSON_OBJECT)? function: tool_call;
						const char *name = json_string (r_json_get (source, "name"));
						const RJson *arguments = r_json_get (source, "arguments");
						if (R_STR_ISEMPTY (name) || !arguments) {
							continue;
						}
						R2AI_ToolCall *tc = R_NEW0 (R2AI_ToolCall);
						const char *tc_id = json_string (r_json_get (tool_call, "id"));
						if (R_STR_ISNOTEMPTY (tc_id)) {
							tc->id = strdup (tc_id);
						}
						if (!tc->id) {
							tc->id = r_str_newf ("call_%zu", i);
						}
						tc->name = strdup (name);
						if (arguments->type == R_JSON_STRING && R_STR_ISNOTEMPTY (arguments->str_value)) {
							tc->arguments = strdup (arguments->str_value);
						} else {
							tc->arguments = r_json_to_string (arguments);
						}
						if (!tc->name || !tc->arguments) {
							r2ai_tool_call_free (tc);
							continue;
						}
						r_list_append (message->tool_calls, tc);
					}
					if (r_list_empty (message->tool_calls)) {
						r_list_free (message->tool_calls);
						message->tool_calls = NULL;
					}
				}
			}
		}
		r_json_free (jres);
		R2AI_ChatResponse *result = R_NEW0 (R2AI_ChatResponse);
		result->message = message;
		result->usage = usage;
		free (res_copy);
		free (auth_header);
		r2ai_msgs_free (temp_msgs);
		free (res);
		return result;
	}

	free (res_copy);
	free (auth_header);
	free (res);
	r2ai_msgs_free (temp_msgs);
	return NULL;
}

R_IPI char *r2ai_openai_stream(RCore *core, R2AIArgs args) {
	(void)core;
	(void)args;
	return NULL;
}
