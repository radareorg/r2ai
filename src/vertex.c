/* Copyright r2ai - 2023-2026 - pancake */

#include "r2ai.h"

#define R2AI_VERTEX_TOKEN_TTL 3300 /* 55 minutes, tokens are valid for ~60 */

static char *vertex_fetch_token(void) {
	char *version = r_sys_cmd_str ("gcloud version", NULL, NULL);
	if (R_STR_ISEMPTY (version)) {
		free (version);
		R_LOG_ERROR ("gcloud CLI not found. Install it from https://cloud.google.com/sdk/docs/install");
		return NULL;
	}
	free (version);
	char *token = r_sys_cmd_str ("gcloud auth application-default print-access-token", NULL, NULL);
	if (R_STR_ISEMPTY (token)) {
		free (token);
		R_LOG_ERROR ("gcloud is not authenticated. Run 'gcloud auth application-default login'");
		return NULL;
	}
	r_str_trim (token);
	if (R_STR_ISEMPTY (token)) {
		free (token);
		return NULL;
	}
	return token;
}

/* The returned pointer is owned by state and must NOT be freed by the caller */
R_IPI const char *r2ai_vertex_get_token(R2AI_State *state) {
	time_t now = time (NULL);
	if (state->vertex_token && now < state->vertex_token_expiry) {
		return state->vertex_token;
	}
	free (state->vertex_token);
	state->vertex_token = vertex_fetch_token ();
	state->vertex_token_expiry = state->vertex_token? now + R2AI_VERTEX_TOKEN_TTL: 0;
	return state->vertex_token;
}

R_IPI R2AI_ChatResponse *r2ai_vertex_gemini(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;
	char **error = args.error;

	const char *project = r_config_get (core->config, "r2ai.vertex.project");
	const char *region = r_config_get (core->config, "r2ai.vertex.region");
	if (R_STR_ISEMPTY (project) || R_STR_ISEMPTY (region)) {
		if (error) {
			*error = strdup ("Set r2ai.vertex.project and r2ai.vertex.region first");
		}
		return NULL;
	}

	const char *model_name = R_STR_ISNOTEMPTY (args.model)
		? args.model
		: r_config_get (core->config, "r2ai.model");

	RList *temp_msgs = r2ai_msgs_new ();
	if (!temp_msgs) {
		if (error) {
			*error = strdup ("Failed to create temporary messages array");
		}
		return NULL;
	}

	const char *system_prompt = NULL;
	if (R_STR_ISNOTEMPTY (args.system_prompt)) {
		system_prompt = args.system_prompt;
	} else {
		system_prompt = r_config_get (core->config, "r2ai.system");
	}

	RListIter *iter;
	R2AI_Message *msg;

	if (args.messages) {
		r_list_foreach (args.messages, iter, msg) {
			r2ai_msgs_add (temp_msgs, msg);
		}
	} else {
		R_LOG_WARN ("No messages");
	}

	if (error) {
		*error = NULL;
	}

	char *auth_header = r_str_newf ("Authorization: Bearer %s", args.api_key);
	const char *headers[] = {
		"Content-Type: application/json",
		auth_header,
		NULL
	};

	char *vertex_url = r_str_newf (
		"https://%s-aiplatform.googleapis.com/v1/projects/%s/locations/%s"
		"/publishers/google/models/%s:generateContent",
		region, project, region, model_name);

	PJ *pj = pj_new ();
	pj_o (pj);

	if (R_STR_ISNOTEMPTY (system_prompt)) {
		pj_ko (pj, "systemInstruction");
		pj_ka (pj, "parts");
		pj_o (pj);
		pj_ks (pj, "text", system_prompt);
		pj_end (pj);
		pj_end (pj);
		pj_end (pj);
	}

	pj_ka (pj, "contents");
	r_list_foreach (temp_msgs, iter, msg) {
		pj_o (pj);
		const char *role = "user";
		if (!strcmp (msg->role, "assistant")) {
			role = "model";
		}
		pj_ks (pj, "role", role);
		pj_ka (pj, "parts");
		pj_o (pj);
		pj_ks (pj, "text", msg->content? msg->content: "");
		pj_end (pj);
		pj_end (pj);
		pj_end (pj);
	}
	pj_end (pj);

	pj_ko (pj, "generationConfig");
	if (args.max_tokens > 0) {
		pj_kn (pj, "maxOutputTokens", args.max_tokens);
	}
	if (args.temperature > 0) {
		pj_kd (pj, "temperature", args.temperature);
	}
	pj_end (pj);

	pj_end (pj);

	char *request_json = pj_drain (pj);

	char *tmpdir = r_file_tmpdir ();
	char *req_path = r_str_newf ("%s" R_SYS_DIR "r2ai_vertex_gemini_request.json", tmpdir);
	r_file_dump (req_path, (const ut8 *)request_json, strlen (request_json), 0);
	R_LOG_DEBUG ("Full request saved to %s", req_path);
	free (req_path);
	free (tmpdir);

	R_LOG_DEBUG ("Vertex Gemini API request data: %s", request_json);

	if (r_config_get_b (core->config, "r2ai.debug")) {
		RStrBuf *curl_cmd = r_strbuf_new ("curl -X POST");
		int i;
		for (i = 0; headers[i]; i++) {
			if (r_str_startswith (headers[i], "Authorization:")) {
				r_strbuf_append (curl_cmd, " -H \"Authorization: Bearer ****\"");
			} else {
				r_strbuf_appendf (curl_cmd, " -H \"%s\"", headers[i]);
			}
		}
		r_strbuf_appendf (curl_cmd, " -d '%s' \"%s\"", request_json, vertex_url);
		eprintf ("Curl command: %s\n", r_strbuf_get (curl_cmd));
		r_strbuf_free (curl_cmd);
	}

	int code = 0;
	char *response = r2ai_http_post (core, vertex_url, headers, request_json, &code, NULL);

	free (request_json);
	free (vertex_url);
	free (auth_header);

	if (code != 200) {
		R_LOG_ERROR ("Vertex Gemini API error %d", code);
		if (response) {
			R_LOG_ERROR ("Vertex Gemini API error response: %s", response);
		}
		free (response);
		r2ai_msgs_free (temp_msgs);
		return NULL;
	}

	tmpdir = r_file_tmpdir ();
	char *res_path = r_str_newf ("%s" R_SYS_DIR "r2ai_vertex_gemini_response.json", tmpdir);
	r_file_dump (res_path, (const ut8 *)response, strlen (response), 0);
	R_LOG_DEBUG ("Vertex Gemini API response saved to %s", res_path);
	free (res_path);
	free (tmpdir);

	RJson *jres = r_json_parse (response);
	if (!jres) {
		if (error) {
			*error = strdup ("Failed to parse Vertex Gemini response JSON");
		}
		free (response);
		r2ai_msgs_free (temp_msgs);
		return NULL;
	}

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

	R2AI_Usage *usage = R_NEW0 (R2AI_Usage);
	const RJson *usage_meta = r_json_get (jres, "usageMetadata");
	if (usage_meta && usage_meta->type == R_JSON_OBJECT) {
		const RJson *pt = r_json_get (usage_meta, "promptTokenCount");
		const RJson *ct = r_json_get (usage_meta, "candidatesTokenCount");
		const RJson *tt = r_json_get (usage_meta, "totalTokenCount");
		if (pt && pt->type == R_JSON_INTEGER) {
			usage->prompt_tokens = pt->num.u_value;
		}
		if (ct && ct->type == R_JSON_INTEGER) {
			usage->completion_tokens = ct->num.u_value;
		}
		if (tt && tt->type == R_JSON_INTEGER) {
			usage->total_tokens = tt->num.u_value;
		}
	}

	r_json_free (jres);
	free (response);
	r2ai_msgs_free (temp_msgs);

	if (!response_text) {
		free (usage);
		return NULL;
	}

	R2AI_Message *message = R_NEW0 (R2AI_Message);
	message->role = strdup ("assistant");
	message->content = response_text;

	R2AI_ChatResponse *result = R_NEW0 (R2AI_ChatResponse);
	result->message = message;
	result->usage = usage;

	return result;
}

/* Vertex Anthropic uses anthropic_version in body instead of header,
 * and omits the model field from the request body */

R_IPI R2AI_ChatResponse *r2ai_vertex_anthropic(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;
	const char *model = args.model;
	char **error = args.error;
	RList *tools = args.tools;
	RList *messages_input = args.messages;

	const char *project = r_config_get (core->config, "r2ai.vertex.project");
	const char *region = r_config_get (core->config, "r2ai.vertex.region");
	if (R_STR_ISEMPTY (project) || R_STR_ISEMPTY (region)) {
		if (error) {
			*error = strdup ("Set r2ai.vertex.project and r2ai.vertex.region first");
		}
		return NULL;
	}

	const char *model_name = R_STR_ISNOTEMPTY (model)
		? model
		: r_config_get (core->config, "r2ai.model");

	if (error) {
		*error = NULL;
	}

	char *auth_header = r_str_newf ("Authorization: Bearer %s", args.api_key);
	const char *headers[] = {
		"Content-Type: application/json",
		auth_header,
		NULL
	};

	char *vertex_url = r_str_newf (
		"https://%s-aiplatform.googleapis.com/v1/projects/%s/locations/%s"
		"/publishers/anthropic/models/%s:rawPredict",
		region, project, region, model_name);

	const char *system_message = NULL;
	if (R_STR_ISNOTEMPTY (args.system_prompt)) {
		system_message = args.system_prompt;
	} else {
		system_message = r_config_get (core->config, "r2ai.system");
	}

	char *messages_json = NULL;
	if (messages_input && !r_list_empty (messages_input)) {
		messages_json = r2ai_msgs_to_anthropic_json (messages_input);
		if (!messages_json) {
			if (error) {
				*error = strdup ("Failed to convert messages to JSON");
			}
			free (auth_header);
			free (vertex_url);
			return NULL;
		}
	} else {
		if (error) {
			*error = strdup ("No input or messages provided");
		}
		free (auth_header);
		free (vertex_url);
		return NULL;
	}

	char *anthropic_tools_json = NULL;
	if (tools && !r_list_empty (tools)) {
		anthropic_tools_json = r2ai_tools_to_anthropic_json (tools);
	}

	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "anthropic_version", "vertex-2023-10-16");
	pj_kn (pj, "max_tokens", args.max_tokens? args.max_tokens: 4096);
	if (args.thinking_tokens >= 1024) {
		pj_ko (pj, "thinking");
		pj_ks (pj, "type", "enabled");
		pj_kn (pj, "budget_tokens", args.thinking_tokens);
		pj_end (pj);
	}
	if (system_message) {
		pj_ks (pj, "system", system_message);
	}

	pj_k (pj, "messages");
	pj_raw (pj, messages_json);

	if (anthropic_tools_json) {
		pj_k (pj, "tools");
		pj_raw (pj, anthropic_tools_json);
		free (anthropic_tools_json);
	}

	pj_kb (pj, "stream", false);

	pj_end (pj);

	char *data = pj_drain (pj);
	free (messages_json);

	char *tmpdir = r_file_tmpdir ();
	char *req_path = r_str_newf ("%s" R_SYS_DIR "r2ai_vertex_anthropic_request.json", tmpdir);
	r_file_dump (req_path, (const ut8 *)data, strlen (data), 0);
	R_LOG_DEBUG ("Full request saved to %s", req_path);
	free (req_path);
	free (tmpdir);

	R_LOG_DEBUG ("Vertex Anthropic API request data: %s", data);

	if (r_config_get_b (core->config, "r2ai.debug")) {
		RStrBuf *curl_cmd = r_strbuf_new ("curl -X POST");
		int i;
		for (i = 0; headers[i]; i++) {
			if (r_str_startswith (headers[i], "Authorization:")) {
				r_strbuf_append (curl_cmd, " -H \"Authorization: Bearer ****\"");
			} else {
				r_strbuf_appendf (curl_cmd, " -H \"%s\"", headers[i]);
			}
		}
		r_strbuf_appendf (curl_cmd, " -d '%s' \"%s\"", data, vertex_url);
		eprintf ("Curl command: %s\n", r_strbuf_get (curl_cmd));
		r_strbuf_free (curl_cmd);
	}

	int code = 0;
	char *res = r2ai_http_post (core, vertex_url, headers, data, &code, NULL);
	free (data);
	free (auth_header);
	free (vertex_url);

	if (!res || code != 200) {
		R_LOG_ERROR ("Vertex Anthropic API error %d", code);
		if (error && res) {
			*error = strdup (res);
		} else if (error) {
			*error = strdup ("Failed to get response from Vertex Anthropic API");
		}
		free (res);
		return NULL;
	}

	tmpdir = r_file_tmpdir ();
	char *res_path = r_str_newf ("%s" R_SYS_DIR "r2ai_vertex_anthropic_response.json", tmpdir);
	r_file_dump (res_path, (const ut8 *)res, strlen (res), 0);
	R_LOG_DEBUG ("Vertex Anthropic API response saved to %s", res_path);
	free (res_path);
	free (tmpdir);

	if (r_config_get_b (core->config, "r2ai.debug")) {
		R_LOG_DEBUG ("Vertex Anthropic API response: %s", res);
	}

	R2AI_ChatResponse *result = r2ai_anthropic_parse_response (res, error);
	free (res);
	return result;
}
