/* r2ai - Copyright 2023-2025 pancake, dnakov */

#include "r2ai.h"

/* Gemini API implementation */

R_IPI R2AI_ChatResponse *r2ai_gemini(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;
	args.model = r_config_get (core->config, "r2ai.model");

	const char *base_url = r2ai_get_provider_url (core, args.provider);
	const char *model_name = args.model && strstr(args.model, "gemini") ? args.model : "gemini-2.0-flash-exp";
	char **error = args.error;

	// Create a temp conversation to include the system prompt and the rest of the messages
	RList *temp_msgs = r2ai_msgs_new ();
	if (!temp_msgs) {
		if (error) {
			*error = strdup ("Failed to create temporary messages array");
		}
		return NULL;
	}

	// Get system prompt
	const char *system_prompt = NULL;
	if (R_STR_ISNOTEMPTY (args.system_prompt)) {
		system_prompt = args.system_prompt;
	} else {
		system_prompt = r_config_get (core->config, "r2ai.system");
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

	if (error) {
		*error = NULL;
	}

	// Setup headers for Gemini API
	const char **headers = NULL;
	char *auth_header = NULL;
	char *api_key_header = NULL;

	if (R_STR_ISNOTEMPTY (args.api_key)) {
		static const char *static_headers[] = { NULL, NULL, NULL };
		headers = static_headers;
		headers[0] = "Content-Type: application/json";

		// Check if it's an OAuth token (starts with "ya29.")
		if (r_str_startswith (args.api_key, "ya29.")) {
			auth_header = r_str_newf ("Authorization: Bearer %s", args.api_key);
			headers[1] = auth_header;
		} else {
			api_key_header = r_str_newf ("x-goog-api-key: %s", args.api_key);
			headers[1] = api_key_header;
		}
	}

	// Build Gemini API URL
	char *gemini_url = r_str_newf ("%s/models/%s:generateContent?key=%s",
		base_url, model_name, args.api_key);

	// Create Gemini-style request JSON
	PJ *pj = pj_new ();
	pj_o (pj);

	// Build contents array
	pj_ka (pj, "contents");
	RListIter *iter;
	R2AI_Message *msg;
	int msg_index = 0;
	r_list_foreach (temp_msgs, iter, msg) {
		pj_o (pj);
		// Gemini uses "model" for assistant, "user" for user
		const char *role = "user";
		if (strcmp (msg->role, "assistant") == 0) {
			role = "model";
		}
		pj_ks (pj, "role", role);
		pj_ka (pj, "parts");
		pj_o (pj);
		// Prepend system prompt to first user message
		char *content = NULL;
		if (system_prompt && strcmp (msg->role, "user") == 0 && msg_index == 0) {
			content = r_str_newf ("System: %s\n\n%s", system_prompt, msg->content ? msg->content : "");
		} else {
			content = msg->content ? strdup (msg->content) : strdup ("");
		}
		pj_ks (pj, "text", content);
		free (content);
		pj_end (pj); // end parts object
		pj_end (pj); // end parts array
		pj_end (pj); // end content object
		msg_index++;
	}
	pj_end (pj); // end contents array

	// Add generation config
	pj_ko (pj, "generationConfig");
	if (args.max_tokens > 0) {
		pj_kn (pj, "maxOutputTokens", args.max_tokens);
	}
	if (args.temperature > 0) {
		pj_kd (pj, "temperature", args.temperature);
	}
	pj_end (pj); // end generationConfig

	pj_end (pj); // end root object

	char *request_json = pj_drain (pj);

	// Debug: save request
	char *tmpdir = r_file_tmpdir ();
	char *req_path = r_str_newf ("%s" R_SYS_DIR "r2ai_gemini_request.json", tmpdir);
	r_file_dump (req_path, (const ut8 *)request_json, strlen (request_json), 0);
	free (req_path);
	free (tmpdir);

	// Make the API call
	char *response = NULL;
	int code = 0;
	response = r2ai_http_post (core, gemini_url, headers, request_json, &code, NULL);

	free (request_json);
	free (gemini_url);
	free (auth_header);
	free (api_key_header);

	if (code != 200) {
		R_LOG_ERROR ("Gemini API error %d", code);
		if (response) {
			R_LOG_ERROR ("Gemini API error response: %s", response);
		}
		free (response);
		r2ai_msgs_free (temp_msgs);
		return NULL;
	}

	// Debug: save response
	tmpdir = r_file_tmpdir ();
	char *res_path = r_str_newf ("%s" R_SYS_DIR "r2ai_gemini_response.json", tmpdir);
	r_file_dump (res_path, (const ut8 *)response, strlen (response), 0);
	free (res_path);
	free (tmpdir);

	// Parse Gemini response
	RJson *jres = r_json_parse (response);
	if (!jres) {
		if (error) {
			*error = strdup ("Failed to parse Gemini response JSON");
		}
		free (response);
		r2ai_msgs_free (temp_msgs);
		return NULL;
	}

	// Extract response content
	const RJson *candidates = r_json_get (jres, "candidates");
	if (!candidates || candidates->type != R_JSON_ARRAY || candidates->children.count == 0) {
		r_json_free (jres);
		free (response);
		r2ai_msgs_free (temp_msgs);
		return NULL;
	}

	const RJson *candidate = r_json_item (candidates, 0);
	const RJson *content = r_json_get (candidate, "content");
	const RJson *parts = r_json_get (content, "parts");

	if (!parts || parts->type != R_JSON_ARRAY || parts->children.count == 0) {
		r_json_free (jres);
		free (response);
		r2ai_msgs_free (temp_msgs);
		return NULL;
	}

	const RJson *part = r_json_item (parts, 0);
	const RJson *text = r_json_get (part, "text");

	char *response_text = NULL;
	if (text && text->type == R_JSON_STRING) {
		response_text = strdup (text->str_value);
	}

	r_json_free (jres);
	free (response);
	r2ai_msgs_free (temp_msgs);

	if (!response_text) {
		return NULL;
	}

	// Create response
	R2AI_Message *message = R_NEW0 (R2AI_Message);
	R2AI_Usage *usage = R_NEW0 (R2AI_Usage);

	if (message) {
		message->role = strdup ("assistant");
		message->content = response_text;
	}

	R2AI_ChatResponse *result = R_NEW0 (R2AI_ChatResponse);
	if (result) {
		result->message = message;
		result->usage = usage;
	}

	return result;
}