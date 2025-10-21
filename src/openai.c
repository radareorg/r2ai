/* r2ai - Copyright 2023-2025 pancake, dnakov */

#include <r_core.h>
#include <r_util/r_json.h>
#include "r2ai.h"

// Bit flags for different types of model errors/incompatibilities
typedef enum {
	MODEL_ERROR_NONE = 0,
	MODEL_ERROR_TEMPERATURE = 1 << 0,
	// Can add more error types here as needed
	// MODEL_ERROR_TOP_P = 1 << 1,
	// MODEL_ERROR_MAX_TOKENS = 1 << 2,
	// etc.
} ModelErrorFlags;

// Structure to store model compatibility info
typedef struct {
	char *model_id; // Provider:model string
	int error_flags; // Bitfield of ModelErrorFlags
} ModelCompat;

// Function to add an error flag to a model
static void model_add_error(R2AI_State *state, const char *provider, const char *model, ModelErrorFlags flag) {
	if (!state) {
		return;
	}

	if (!state->model_compat_db) {
		state->model_compat_db = ht_pp_new0 ();
	}

	char *key = r_str_newf ("%s:%s", provider, model? model: "default");
	bool found_flag = false;
	ModelCompat *compat = ht_pp_find (state->model_compat_db, key, &found_flag);

	if (found_flag && compat) {
		// Update existing entry
		compat->error_flags |= flag;
	} else {
		// Create new entry
		compat = R_NEW0 (ModelCompat);
		compat->model_id = strdup (key);
		compat->error_flags = flag;
		ht_pp_insert (state->model_compat_db, key, compat);
	}
	free (key);
}

// Free a ModelCompat item (for hash table)
static bool model_compat_free_cb(void *user, const void *k, const void *v) {
	(void)user;
	(void)k;
	ModelCompat *compat = (ModelCompat *)v;
	if (compat) {
		free (compat->model_id);
		free (compat);
	}
	return true;
}

// Function to free the model_compat_db hash table
R_IPI void r2ai_openai_fini(R2AI_State *state) {
	if (state && state->model_compat_db) {
		ht_pp_foreach (state->model_compat_db, model_compat_free_cb, NULL);
		ht_pp_free (state->model_compat_db);
		state->model_compat_db = NULL;
	}
}

R_IPI R2AI_ChatResponse *r2ai_openai(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	// Initialize compatibility database if needed
	if (!state->model_compat_db) {
		state->model_compat_db = ht_pp_new0 ();
	}

	const char *base_url = r2ai_get_provider_url (core, args.provider);
	// TODO: default model name should depend on api
	const char *model_name = args.model? args.model: "gpt-4o-mini";
	char **error = args.error;
	const R2AI_Tools *tools = args.tools;
	// create a temp conversation to include the system prompt and the rest of the messages
	R2AI_Messages *temp_msgs = r2ai_msgs_new ();
	if (!temp_msgs) {
		if (error) {
			*error = strdup ("Failed to create temporary messages array");
		}
		return NULL;
	}
	R2AI_Message system_msg = {
		.role = "system",
		.content = args.system_prompt
	};
	// Add system message if available from args.system_prompt
	if (R_STR_ISNOTEMPTY (args.system_prompt)) {
		R_LOG_DEBUG ("Using system prompt: %s", args.system_prompt);
		// if the model name contains "o1" or "o3", it's "developer" role
		if (strstr (model_name, "o1") || strstr (model_name, "o3")) {
			system_msg.role = "developer";
			system_msg.content = args.system_prompt;
		} else {
			system_msg.role = "system";
			system_msg.content = args.system_prompt;
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
			system_msg.content = sysprompt;
			r2ai_msgs_add (temp_msgs, &system_msg);
		}
	}
	if (args.messages) {
		for (int i = 0; i < r_list_length (args.messages->messages); i++) {
			r2ai_msgs_add (temp_msgs, r_list_get_n (args.messages->messages, i));
		}
	} else {
		R_LOG_WARN ("No messages");
	}
	// Safely print debug info about first message
	if (temp_msgs && r_list_length (temp_msgs->messages) > 0 && ((R2AI_Message *)r_list_get_n (temp_msgs->messages, 0))->role) {
		R_LOG_DEBUG ("First message role: %s", ((R2AI_Message *)r_list_get_n (temp_msgs->messages, 0))->role);
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
	if (!args.provider) {
		return NULL;
	}
	const char *urlfmt = strcmp (args.provider, "ollama")
		? "%s/chat/completions"
		: "%s/chat";
	char *openai_url = r_str_newf (urlfmt, base_url);

	// Create a messages JSON object, either from input messages or from content
	char *messages_json = NULL;

	if (temp_msgs && r_list_length (temp_msgs->messages) > 0) {
		R_LOG_DEBUG ("Using input messages: %d messages", r_list_length (temp_msgs->messages));
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
	if (tools && tools->n_tools > 0) {
		openai_tools_json = r2ai_tools_to_openai_json (tools);
	}

	// Create the model settings part
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "model", model_name);
	pj_kb (pj, "stream", false);

	if (strcmp (args.provider, "ollama") == 0) {
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
	// XXX: only create request/response files when r2ai.debug is set
	char *tmpdir = r_file_tmpdir ();
	char *req_path = r_str_newf ("%s" R_SYS_DIR "r2ai_openai_request.json", tmpdir);
	r_file_dump (req_path, (const ut8 *)complete_json, strlen (complete_json), 0);
	R_LOG_DEBUG ("Full request saved to %s", req_path);
	free (req_path);
	free (tmpdir);

	R_LOG_DEBUG ("OpenAI API request data: %s", complete_json);

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
			// Check for specific error types in the response
			ModelErrorFlags error_flag = MODEL_ERROR_NONE;
			const char *model_name = args.model? args.model: "gpt-5-mini";

			// Check for temperature errors
			if (strstr (res, "temperature")) {
				R_LOG_DEBUG ("Detected temperature error for %s model %s", args.provider, model_name);
				error_flag |= MODEL_ERROR_TEMPERATURE;
			}

			if (error_flag != MODEL_ERROR_NONE) {
				// Record the error flags for this provider/model
				model_add_error (state, args.provider, model_name, error_flag);

				// Clean up
				free (auth_header);
				free (res);

				// Retry the call (it will skip problematic parameters this time)
				R_LOG_INFO ("Retrying request with adjusted parameters for %s/%s", args.provider, model_name);
				RCorePluginSession retry_cps = { .core = core, .data = state };
				return r2ai_openai (&retry_cps, args);
			}
		}
		free (auth_header);
		free (res);
		return NULL;
	}

	// Save the response for inspection
	tmpdir = r_file_tmpdir ();
	char *res_path = r_str_newf ("%s" R_SYS_DIR "r2ai_openai_response.json", tmpdir);
	r_file_dump (res_path, (const ut8 *)res, strlen (res), 0);
	R_LOG_DEBUG ("OpenAI API response saved to %s", res_path);
	free (res_path);
	free (tmpdir);

	R_LOG_DEBUG ("OpenAI API response: %s", res);

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
			if (strcmp (args.provider, "ollama") == 0) {
				// Ollama has usage info at top level
				usage_json = jres;
			} else {
				usage_json = r_json_get (jres, "usage");
			}

			if (usage_json && usage_json->type == R_JSON_OBJECT) {
				if (strcmp (args.provider, "ollama") == 0) {
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
			if (strcmp (args.provider, "ollama") == 0) {
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

				// Set the basic message properties
				message->role = (role && role->type == R_JSON_STRING)? strdup (role->str_value): strdup ("assistant");

				if (content && content->type == R_JSON_STRING) {
					message->content = strdup (content->str_value);
				}

				if (reasoning_content && reasoning_content->type == R_JSON_STRING) {
					message->reasoning_content = strdup (reasoning_content->str_value);
				}

				// TODO: Handle tool calls if present
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
