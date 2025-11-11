/* r2ai - Copyright 2023-2025 pancake, dnakov */

#include "r2ai.h"
#include "r2ai_priv.h"

R_IPI R2AI_ChatResponse *r2ai_openai(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;
	args.provider = r_config_get (core->config, "r2ai.api");
	args.model = r_config_get (core->config, "r2ai.model");

	const R2AIProvider *provider_info = r2ai_get_provider (args.provider);
	const char *base_url = r2ai_get_provider_url (core, args.provider);
	// TODO: default model name should depend on api
	const char *model_name = args.model? args.model: "gpt-4o-mini";
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
	const char *urlfmt = (provider_info && provider_info->api_type == R2AI_API_OLLAMA)
		? "%s/chat"
		: "%s/chat/completions";
	char *openai_url = r_str_newf (urlfmt, base_url);

	// Create a messages JSON object, either from input messages or from content
	char *messages_json = NULL;

	if (temp_msgs && !r_list_empty (temp_msgs)) {
		R_LOG_DEBUG ("Using input messages: %d messages", r_list_length (temp_msgs));
		messages_json = r2ai_msgs_to_json (temp_msgs);
		if (!messages_json) {
			if (error) {
				*error = strdup ("Failed to convert messages to JSON");
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
		openai_tools_json = r2ai_tools_to_openai_json (tools);
	}

	// Create the model settings part
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "model", model_name);
	pj_kb (pj, "stream", false);

	if (provider_info && provider_info->api_type == R2AI_API_OLLAMA) {
		// Ollama uses "options" object for parameters
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

		if (strcmp (args.provider, "mistral") == 0) {
			pj_kn (pj, "max_tokens", args.max_tokens? args.max_tokens: 5128);
		} else {
			pj_kn (pj, "max_completion_tokens", args.max_tokens? args.max_tokens: 5128);
		}
	}

	pj_end (pj);

	// Get the JSON for model settings
	char *model_json = pj_drain (pj);

	// Manually create the final JSON by combining parts
	// Remove the closing brace from model_json
	size_t model_len = strlen (model_json);
	if (model_len > 0 && model_json[model_len - 1] == '}') {
		model_json[model_len - 1] = '\0';
	}

	// Create the full JSON with proper structure
	char *complete_json;
	if (openai_tools_json) {
		complete_json = r_str_newf ("%s, \"messages\": %s, \"tools\": %s}",
			model_json, messages_json, openai_tools_json);
		free (openai_tools_json);
	} else {
		complete_json = r_str_newf ("%s, \"messages\": %s}",
			model_json, messages_json);
	}

	// Free intermediate strings
	free (model_json);
	free (messages_json);

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
		for (int i = 0; headers[i]; i++) {
			r_strbuf_appendf (curl_cmd, " -H \"%s\"", headers[i]);
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
		// Create a new message structure
		R2AI_Message *message = R_NEW0 (R2AI_Message);
		R2AI_Usage *usage = R_NEW0 (R2AI_Usage);
		if (message) {
			// Process the response using our r2ai_msgs_from_json logic
			const RJson *usage_json = NULL;
			if (provider_info && provider_info->api_type == R2AI_API_OLLAMA) {
				// Ollama has usage info at top level
				usage_json = jres;
			} else {
				usage_json = r_json_get (jres, "usage");
			}

			if (usage_json && usage_json->type == R_JSON_OBJECT) {
				if (provider_info && provider_info->api_type == R2AI_API_OLLAMA) {
					// Ollama field names
					const RJson *prompt_tokens = r_json_get (usage_json, "prompt_eval_count");
					const RJson *completion_tokens = r_json_get (usage_json, "eval_count");
					if (prompt_tokens && prompt_tokens->type == R_JSON_INTEGER) {
						usage->prompt_tokens = prompt_tokens->num.u_value;
					}
					if (completion_tokens && completion_tokens->type == R_JSON_INTEGER) {
						usage->completion_tokens = completion_tokens->num.u_value;
					}
					// Calculate total_tokens for ollama
					usage->total_tokens = usage->prompt_tokens + usage->completion_tokens;
				} else {
					// OpenAI field names
					const RJson *prompt_tokens = r_json_get (usage_json, "prompt_tokens");
					const RJson *completion_tokens = r_json_get (usage_json, "completion_tokens");
					const RJson *total_tokens = r_json_get (usage_json, "total_tokens");
					if (prompt_tokens && prompt_tokens->type == R_JSON_INTEGER) {
						usage->prompt_tokens = prompt_tokens->num.u_value;
					}
					if (completion_tokens && completion_tokens->type == R_JSON_INTEGER) {
						usage->completion_tokens = completion_tokens->num.u_value;
					}
					if (total_tokens && total_tokens->type == R_JSON_INTEGER) {
						usage->total_tokens = total_tokens->num.u_value;
					}
				}
			}
			const RJson *message_json = NULL;
			if (provider_info && provider_info->api_type == R2AI_API_OLLAMA) {
				// Ollama returns message directly
				message_json = r_json_get (jres, "message");
			} else {
				// OpenAI-style response with choices array
				const RJson *choices = r_json_get (jres, "choices");
				if (choices && choices->type == R_JSON_ARRAY) {
					const RJson *choice = r_json_item (choices, 0);
					if (choice) {
						message_json = r_json_get (choice, "message");
					}
				}
			}

			if (message_json) {
				const RJson *role = r_json_get (message_json, "role");
				const RJson *content = r_json_get (message_json, "content");
				const RJson *reasoning_content = r_json_get (message_json, "reasoning_content");
				const RJson *thinking = r_json_get (message_json, "thinking");
				const RJson *tool_call_id = r_json_get (message_json, "tool_call_id");
				const RJson *tool_calls = r_json_get (message_json, "tool_calls");

				// Set the basic message properties
				message->role = (role && role->type == R_JSON_STRING)? strdup (role->str_value): strdup ("assistant");

				if (content && content->type == R_JSON_STRING) {
					message->content = strdup (content->str_value);
				}

				if (reasoning_content && reasoning_content->type == R_JSON_STRING && R_STR_ISNOTEMPTY (reasoning_content->str_value)) {
					message->reasoning_content = strdup (reasoning_content->str_value);
				} else if (thinking && thinking->type == R_JSON_STRING && R_STR_ISNOTEMPTY (thinking->str_value)) {
					message->reasoning_content = strdup (thinking->str_value);
				}

				if (tool_call_id && tool_call_id->type == R_JSON_STRING && R_STR_ISNOTEMPTY (tool_call_id->str_value)) {
					message->tool_call_id = strdup (tool_call_id->str_value);
				}

				if (tool_calls && tool_calls->type == R_JSON_ARRAY && tool_calls->children.count > 0) {
					message->tool_calls = r_list_new ();
					if (message->tool_calls) {
						message->tool_calls->free = (RListFree)r2ai_tool_call_free;
						for (size_t i = 0; i < tool_calls->children.count; i++) {
							const RJson *tool_call = r_json_item (tool_calls, i);
							if (!tool_call || tool_call->type != R_JSON_OBJECT) {
								continue;
							}
							R2AI_ToolCall *tc = R_NEW0 (R2AI_ToolCall);
							if (!tc) {
								continue;
							}
							const RJson *tc_id = r_json_get (tool_call, "id");
							if (tc_id && tc_id->type == R_JSON_STRING && R_STR_ISNOTEMPTY (tc_id->str_value)) {
								tc->id = strdup (tc_id->str_value);
							}
							const RJson *function = r_json_get (tool_call, "function");
							const RJson *name_json = NULL;
							const RJson *arguments = NULL;
							if (function && function->type == R_JSON_OBJECT) {
								name_json = r_json_get (function, "name");
								arguments = r_json_get (function, "arguments");
							} else {
								name_json = r_json_get (tool_call, "name");
								arguments = r_json_get (tool_call, "arguments");
							}
							if (name_json && name_json->type == R_JSON_STRING && R_STR_ISNOTEMPTY (name_json->str_value)) {
								tc->name = strdup (name_json->str_value);
							}
							if (arguments) {
								if (arguments->type == R_JSON_STRING && R_STR_ISNOTEMPTY (arguments->str_value)) {
									tc->arguments = strdup (arguments->str_value);
								} else {
									char *arguments_json = r_json_to_string (arguments);
									if (arguments_json) {
										tc->arguments = arguments_json;
									}
								}
							}
							if (!tc->name && !tc->arguments && !tc->id) {
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
				// TODO: Handle tool calls if present?
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
