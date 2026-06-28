/* r2ai - Copyright 2023-2026 pancake, dnakov */

#include "r2ai.h"
#include "r2ai_priv.h"

static const char *json_string(const RJson *json) {
	return (json && json->type == R_JSON_STRING)? json->str_value: NULL;
}

static uint64_t json_integer(const RJson *json) {
	return (json && json->type == R_JSON_INTEGER)? json->num.u_value: 0;
}

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

R_IPI R2AI_ChatResponse *r2ai_openai(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;
	const char *provider_name = R_STR_ISNOTEMPTY (args.provider)
		? args.provider
		: r_config_get (core->config, "r2ai.api");
	const char *model_name = R_STR_ISNOTEMPTY (args.model)
		? args.model
		: r_config_get (core->config, "r2ai.model");

	const R2AIProvider *provider_info = r2ai_get_provider (provider_name);
	const bool is_ollama = provider_info && provider_info->api_type == R2AI_API_OLLAMA;
	const bool use_generate = is_ollama && is_generate_api (core);
	const char *base_url = r2ai_get_provider_url (core, provider_name);
	// TODO: default model name should depend on api
	model_name = model_name? model_name: "gpt-4o-mini";
	char **error = args.error;
	RList *tools = args.tools;
	// create a temp conversation to include the system prompt and the rest of the messages
	RList *temp_msgs = r2ai_msgs_new ();
	if (!temp_msgs) {
		if (error) {
			*error = strdup ("Failed to create temporary messages array");
		}
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

	const char **headers = NULL;
	char *auth_header = NULL;
	if (R_STR_ISNOTEMPTY (args.api_key)) {
		auth_header = r_str_newf ("Authorization: Bearer %s", args.api_key);
		R_LOG_DEBUG ("Auth header: %s", auth_header);
		static const char *static_headers[] = { NULL, NULL, NULL };
		headers = static_headers;
		headers[0] = "Content-Type: application/json";
		headers[1] = auth_header;
	}
	const char *urlfmt = is_ollama
		? (use_generate? "%s/generate": "%s/chat")
		: "%s/chat/completions";
	char *openai_url = r_str_newf (urlfmt, base_url);

	// Prepare the input messages in the shape required by the selected endpoint.
	char *chat_messages_json = NULL;
	char *generate_prompt = NULL;
	char *generate_system = NULL;

	if (temp_msgs && !r_list_empty (temp_msgs)) {
		R_LOG_DEBUG ("Using input messages: %d messages", r_list_length (temp_msgs));
		if (use_generate) {
			generate_prompt = ollama_generate_prompt_from_messages (temp_msgs, &generate_system);
		} else {
			chat_messages_json = r2ai_msgs_to_json (temp_msgs, is_ollama);
		}
		if (!chat_messages_json && !generate_prompt) {
			if (error) {
				*error = strdup ("Failed to prepare messages for request");
			}
			free (auth_header);
			return NULL;
		}
	} else {
		if (error) {
			*error = strdup ("No messages provided");
		}
		free (auth_header);
		return NULL;
	}

	// Convert tools to OpenAI format if available
	char *openai_tools_json = NULL;
	if (tools && !r_list_empty (tools)) {
		if (use_generate) {
			R_LOG_DEBUG ("Skipping native tool definitions for /api/generate payload");
		} else {
			openai_tools_json = r2ai_tools_to_openai_json (tools);
		}
	}

	// Create the model settings part
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "model", model_name);
	pj_kb (pj, "stream", false);

	if (is_ollama) {
		pj_kb (pj, "think", args.thinking_tokens > 0);
		pj_ko (pj, "options");
		if (args.max_tokens) {
			pj_kn (pj, "num_predict", args.max_tokens);
		}
		if (args.temperature > 0) {
			pj_kd (pj, "temperature", args.temperature);
		}
		pj_end (pj); // end options
	} else {
#if 0
		// gpt-5-mini-chat is the only gpt-5 model that supports temperature
		// gpt-5 gpt-5-mini and gpt-5-nano just throw an error
		// Only add temperature if this provider/model doesn't have the temperature error flag
		if (!model_has_error (args.provider, model_name, MODEL_ERROR_TEMPERATURE)) {
			pj_kd (pj, "temperature", args.temperature? args.temperature: 0.01);
		}
#endif

		if (!strcmp (provider_name, "mistral")) {
			pj_kn (pj, "max_tokens", args.max_tokens? args.max_tokens: 5128);
		} else {
			pj_kn (pj, "max_completion_tokens", args.max_tokens? args.max_tokens: 5128);
		}
	}
	if (use_generate) {
		pj_ks (pj, "prompt", generate_prompt);
		if (R_STR_ISNOTEMPTY (generate_system)) {
			pj_ks (pj, "system", generate_system);
		}
	} else {
		pj_k (pj, "messages");
		pj_raw (pj, chat_messages_json);
		if (openai_tools_json) {
			pj_k (pj, "tools");
			pj_raw (pj, openai_tools_json);
		}
	}
	pj_end (pj);

	char *complete_json = pj_drain (pj);
	if (!use_generate) {
		check_chat_cache (cps, provider_name, model_name, openai_tools_json, chat_messages_json);
	}
	free (chat_messages_json);
	free (generate_prompt);
	free (generate_system);
	free (openai_tools_json);

	if (!complete_json) {
		if (error) {
			*error = strdup ("Failed to create complete request JSON");
		}
		free (auth_header);
		return NULL;
	}

	// Save the full JSON to a file for inspection
	// XXX: only create request/response files when r2ai.debug is set
	char *tmpdir = r_file_tmpdir ();
	char *req_path = r_str_newf ("%s" R_SYS_DIR "r2ai_openai_request.json", tmpdir);
	r_file_dump (req_path, (const ut8 *)complete_json, strlen (complete_json), 0);
	R_LOG_DEBUG ("Full request saved to %s", req_path);
	free (req_path);
	free (tmpdir);

	R_LOG_DEBUG ("OpenAI API request data: %s", complete_json);

	if (r_config_get_b (core->config, "r2ai.debug")) {
		// Generate curl command for debugging
		RStrBuf *curl_cmd = r_strbuf_new ("curl -X POST");
		if (headers) {
			for (int i = 0; headers[i]; i++) {
				r_strbuf_appendf (curl_cmd, " -H \"%s\"", headers[i]);
			}
		}
		r_strbuf_appendf (curl_cmd, " -d '%s' \"%s\"", complete_json, openai_url);
		eprintf ("Curl command: %s\n", r_strbuf_get (curl_cmd));
		r_strbuf_free (curl_cmd);
	}

	// Make the API call
	char *res = NULL;
	int code = 0;
	res = r2ai_http_post (core, openai_url, headers, complete_json, &code, NULL);
	free (complete_json);
	free (openai_url);

	if (code != 200) {
		R_LOG_ERROR ("OpenAI API error %d", code);
		if (res) {
			R_LOG_ERROR ("OpenAI API error response: %s", res);
		}
		free (auth_header);
		free (res);
		return NULL;
	}

	// Save the response for inspection
	tmpdir = r_file_tmpdir ();
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
		R2AI_Message *message = R_NEW0 (R2AI_Message);
		R2AI_Usage *usage = R_NEW0 (R2AI_Usage);
		const RJson *usage_json = is_ollama? jres: r_json_get (jres, "usage");
		if (usage_json && usage_json->type == R_JSON_OBJECT) {
			usage->prompt_tokens = json_integer (r_json_get (usage_json, is_ollama? "prompt_eval_count": "prompt_tokens"));
			usage->completion_tokens = json_integer (r_json_get (usage_json, is_ollama? "eval_count": "completion_tokens"));
			usage->total_tokens = is_ollama
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
		} else if (is_ollama) {
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

	free (auth_header);
	free (res);
	return NULL;
}

R_IPI char *r2ai_openai_stream(RCore *core, R2AIArgs args) {
	(void)core;
	(void)args;
	return NULL;
}
