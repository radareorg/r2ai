#include <r_core.h>
#include <r_util/r_json.h>
#include "r2ai.h"

#if R2_VERSION_NUMBER >= 50909

R_IPI R2AI_ChatResponse *r2ai_openai (RCore *core, R2AIArgs args) {
	const char *base_url = r_config_get (core->config, "r2ai.base_url");

	if (R_STR_ISEMPTY (base_url)) {
		if (strcmp (args.provider, "openai") == 0) {
			base_url = "https://api.openai.com/v1";
		} else if (strcmp (args.provider, "gemini") == 0) {
			base_url = "https://generativelanguage.googleapis.com/v1beta/openai";
		} else if (strcmp (args.provider, "ollama") == 0) {
			base_url = "http://localhost:11434/v1";
		} else if (strcmp (args.provider, "xai") == 0) {
			base_url = "https://api.x.ai/v1";
		} else if (strcmp (args.provider, "anthropic") == 0) {
			base_url = "https://api.anthropic.com/v1";
		} else if (strcmp (args.provider, "openapi") == 0) {
			base_url = "http://127.0.0.1:11434";
		} else if (strcmp (args.provider, "openrouter") == 0) {
			base_url = "https://openrouter.ai/api/v1";
		}
	}

	const char *content = args.input;
	char **error = args.error;
	const R2AI_Tools *tools = args.tools;
	R2AI_Messages *messages_input = args.messages;

	if (error) {
		*error = NULL;
	}

	char *auth_header = r_str_newf ("Authorization: Bearer %s", args.api_key);
	R_LOG_INFO ("Auth header: %s", auth_header);
	const char *headers[] = { "Content-Type: application/json", auth_header, NULL };
	const char *openai_url = r_str_newf ("%s/chat/completions", base_url);

	// Create a messages JSON object, either from input messages or from content
	char *messages_json = NULL;

	if (messages_input && messages_input->n_messages > 0) {
		R_LOG_INFO ("Using input messages: %d messages", messages_input->n_messages);
		messages_json = r2ai_msgs_to_json (messages_input);
		if (!messages_json) {
			if (error) {
				*error = strdup ("Failed to convert messages to JSON");
			}
			free (auth_header);
			return NULL;
		}
	} else if (content) {
		// Create a temporary messages array for the simple content-based message
		R2AI_Messages *temp_msgs = r2ai_msgs_new ();
		if (!temp_msgs) {
			if (error) {
				*error = strdup ("Failed to create temporary messages array");
			}
			free (auth_header);
			return NULL;
		}

		// Add system message if available from args.system_prompt
		if (R_STR_ISNOTEMPTY (args.system_prompt)) {
			R2AI_Message system_msg = {
				.role = "system",
				.content = args.system_prompt
			};
			r2ai_msgs_add (temp_msgs, &system_msg);
		} else {
			// Fallback to config if args.system_prompt is not set
			const char *sysprompt = r_config_get (core->config, "r2ai.system");
			if (R_STR_ISNOTEMPTY (sysprompt)) {
				R2AI_Message system_msg = {
					.role = "system",
					.content = sysprompt
				};
				r2ai_msgs_add (temp_msgs, &system_msg);
			}
		}

		// Add user message with content
		R2AI_Message user_msg = {
			.role = "user",
			.content = content
		};
		r2ai_msgs_add (temp_msgs, &user_msg);

		// Convert to JSON
		messages_json = r2ai_msgs_to_json (temp_msgs);

		// Free the temporary messages
		r2ai_msgs_free (temp_msgs);

		if (!messages_json) {
			if (error) {
				*error = strdup ("Failed to convert messages to JSON");
			}
			free (auth_header);
			return NULL;
		}
	} else {
		if (error) {
			*error = strdup ("No input or messages provided");
		}
		free (auth_header);
		return NULL;
	}

	// Convert tools to OpenAI format if available
	char *openai_tools_json = NULL;
	if (tools && tools->n_tools > 0) {
		openai_tools_json = r2ai_tools_to_openai_json (tools);
	}

	// Create the model settings part
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "model", args.model ? args.model : "gpt-4o-mini");
	pj_kb (pj, "stream", false);
	pj_kn (pj, "max_completion_tokens", 5128);
	pj_end (pj);

	// Get the JSON for model settings
	char *model_json = pj_drain (pj);
	if (!model_json) {
		if (error) {
			*error = strdup ("Failed to create model settings JSON");
		}
		free (auth_header);
		free (messages_json);
		if (openai_tools_json) {
			free (openai_tools_json);
		}
		return NULL;
	}

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
	r_file_dump ("/tmp/r2ai_openai_request.json", (const ut8 *)complete_json, strlen (complete_json), 0);
	R_LOG_INFO ("Full request saved to /tmp/r2ai_openai_request.json");
	R_LOG_INFO ("OpenAI API request data: %s", complete_json);

	// Make the API call
	char *res = NULL;
	int code = 0;
	res = r_socket_http_post (openai_url, headers, complete_json, &code, NULL);
	free (complete_json);

	if (code != 200) {
		R_LOG_ERROR ("OpenAI API error %d", code);
		if (res) {
			R_LOG_ERROR ("Error response: %s", res);
		}
		free (auth_header);
		free (res);
		return NULL;
	}

	// Save the response for inspection
	r_file_dump ("/tmp/r2ai_openai_response.json", (const ut8 *)res, strlen (res), 0);
	R_LOG_INFO ("OpenAI API response saved to /tmp/r2ai_openai_response.json");
	R_LOG_INFO ("OpenAI API response: %s", res);

	// Parse the response into our messages structure

	char *res_copy = strdup (res);
	RJson *jres = r_json_parse (res_copy);
	if (jres) {
		// Create a new message structure
		R2AI_Message *message = R_NEW0 (R2AI_Message);
		R2AI_Usage *usage = R_NEW0 (R2AI_Usage);
		if (message) {
			// Process the response using our r2ai_msgs_from_json logic
			const RJson *usage_json = r_json_get (jres, "usage");
			if (usage_json && usage_json->type == R_JSON_OBJECT) {
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
			const RJson *choices = r_json_get (jres, "choices");
			if (choices && choices->type == R_JSON_ARRAY) {
				const RJson *choice = r_json_item (choices, 0);
				if (choice) {
					const RJson *message_json = r_json_get (choice, "message");
					if (message_json) {
						const RJson *role = r_json_get (message_json, "role");
						const RJson *content = r_json_get (message_json, "content");

						// Set the basic message properties
						message->role = (role && role->type == R_JSON_STRING) ? strdup (role->str_value) : strdup ("assistant");

						if (content && content->type == R_JSON_STRING) {
							message->content = strdup (content->str_value);
						}

						// Handle tool calls if present
						const RJson *tool_calls = r_json_get (message_json, "tool_calls");
						if (tool_calls && tool_calls->type == R_JSON_ARRAY && tool_calls->children.count > 0) {
							int n_tool_calls = tool_calls->children.count;
							R2AI_ToolCall *tool_calls_array = R_NEWS0 (R2AI_ToolCall, n_tool_calls);

							if (tool_calls_array) {
								for (size_t i = 0; i < n_tool_calls; i++) {
									const RJson *tool_call = r_json_item (tool_calls, i);
									if (!tool_call) {
										continue;
									}

									const RJson *id = r_json_get (tool_call, "id");
									const RJson *function = r_json_get (tool_call, "function");
									if (!function) {
										continue;
									}

									const RJson *name = r_json_get (function, "name");
									const RJson *arguments = r_json_get (function, "arguments");

									if (id && id->type == R_JSON_STRING) {
										tool_calls_array[i].id = strdup (id->str_value);
									}

									if (name && name->type == R_JSON_STRING) {
										tool_calls_array[i].name = strdup (name->str_value);
									}

									if (arguments && arguments->type == R_JSON_STRING) {
										tool_calls_array[i].arguments = strdup (arguments->str_value);
									}
								}

								message->tool_calls = tool_calls_array;
								message->n_tool_calls = n_tool_calls;
							}
						}
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
		free (res);
		return result;
	}

	free (auth_header);
	free (res);
	return NULL;
}

R_IPI char *r2ai_openai_stream (RCore *core, R2AIArgs args) {

	return NULL;
}

#endif
