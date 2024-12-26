#include "r2ai.h"

#if R2_VERSION_NUMBER >= 50909

static bool handle_xai_stream_chunk(const char *chunk) {
	if (R_STR_ISEMPTY (chunk)) {
		return false;
	}

	if (!r_str_startswith (chunk, "data:")) {
		return false;
	}

	const char *data = r_str_trim_head_ro (chunk + 6);
	if (R_STR_ISEMPTY (data)) {
		return false;
	}

	char *data_copy = strdup (data);
	RJson *jres = r_json_parse (data_copy);
	if (!jres) {
		free (data_copy);
		return false;
	}

	const RJson *candidates = r_json_get (jres, "candidates");
	if (candidates && candidates->type == R_JSON_ARRAY) {
		const RJson *first = r_json_item (candidates, 0);
		if (first) {
			const RJson *content = r_json_get (first, "content");
			if (content) {
				const RJson *parts = r_json_get (content, "parts");
				if (parts && parts->type == R_JSON_ARRAY) {
					const RJson *part = r_json_item (parts, 0);
					if (part) {
						const RJson *text = r_json_get (part, "text");
						if (text && text->str_value) {
							eprintf ("%s", text->str_value);
						}
					}
				}
			}
		}
	}

	r_json_free (jres);
	free (data_copy);
	return false;
}

R_IPI char *r2ai_xai(RCore *core, const char *content, char **error) {
	if (!content) {
		if (error) {
			*error = strdup("Content cannot be null");
		}
		return NULL;
	}

	if (error) {
		*error = NULL;
	}

	char *apikey = r_sys_getenv ("XAI_API_KEY");
	if (!apikey) {
		char *apikey_file = r_file_new ("~/.r2ai.xai-key", NULL);
		apikey = r_file_slurp (apikey_file, NULL);
		free (apikey_file);
		if (!apikey) {
			if (error) {
				*error = strdup ("Failed to read X.AI API key from XAI_API_KEY env or ~/.r2ai.xai-key");
			}
			return NULL;
		}
		r_str_trim (apikey);
	}

	char *authorization_bearer = r_str_newf ("Authorization: Bearer %s", apikey);
	const char *headers[] = {
		"Content-Type: application/json",
		authorization_bearer,
		NULL
	};

	const char *base_url = "https://api.x.ai/v1/chat/completions";
	const char *actual_model = r_config_get (core->config, "r2ai.model");
	char *url = r_str_newf ("%s/%s:generateContent?key=%s",
		base_url,
		actual_model? actual_model: "xai-1.5-pro",
		apikey);

	R_LOG_DEBUG ("X.AI API URL: %s", url);

	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ka (pj, "contents");
	pj_o (pj);
	pj_ks (pj, "role", "user");
	pj_ka (pj, "parts");
	pj_o (pj);
	pj_ks (pj, "text", content);
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);

	char *data = pj_drain (pj);
	R_LOG_DEBUG ("X.AI API request data: %s", data);
	int code = 0;
	char *res = r_socket_http_post (url, headers, data, &code, NULL);
	free (authorization_bearer);

	if (res) {
		R_LOG_DEBUG ("X.AI API response: %s", res);
	}

	if (!res || code != 200) {
		R_LOG_ERROR ("X.AI API error %d", code);
		if (res) {
			R_LOG_ERROR ("Error response: %s", res);
		}
		if (error) {
			*error = strdup (res? res: "Failed to get response from X.AI API");
		}
		free (apikey);
		free (url);
		free (data);
		free (res);
		return NULL;
	}

	char *res_content = NULL;
	RJson *jres = r_json_parse (res);
	if (jres) {
		const RJson *jres_choices = r_json_get (jres, "choices");
		if (jres_choices) {
			const RJson *jres_choices0 = r_json_item (jres_choices, 0);
			if (jres_choices0) {
				const RJson *jres_message = r_json_get (jres_choices0, "message");
				if (jres_message) {
					const RJson *jres_content = r_json_get (jres_message, "content");
					if (jres_content) {
						res_content = strdup (jres_content->str_value);
					}
				}
			}
		}
		r_json_free (jres);
	}

	free (apikey);
	free (url);
	free (data);
	free (res);
	return res_content;
}

R_IPI char *r2ai_xai_stream(RCore *core, const char *content, char **error) {
	if (!content) {
		if (error) {
			*error = strdup ("Content cannot be null");
		}
		return NULL;
	}

	if (error) {
		*error = NULL;
	}

	char *apikey = r_sys_getenv ("XAI_API_KEY");
	if (!apikey) {
		char *apikey_file = r_file_new ("~/.r2ai.xai-key", NULL);
		apikey = r_file_slurp (apikey_file, NULL);
		free (apikey_file);
		if (!apikey) {
			if (error) {
				*error = strdup ("Failed to read X.AI API key from XAI_API_KEY env or ~/.r2ai.xai-key");
			}
			return NULL;
		}
		r_str_trim (apikey);
	}

	char *authorization_bearer = r_str_newf ("Authorization: Bearer %s", apikey);
	const char *headers[] = {
		"Content-Type: application/json",
		authorization_bearer,
		NULL
	};

	const char *base_url = "https://api.x.ai/v1beta/models";
	const char *actual_model = r_config_get (core->config, "r2ai.model");
	char *url = r_str_newf ("%s/%s", base_url, actual_model? actual_model: "xai-1.5-pro");

	R_LOG_DEBUG ("X.AI API URL: %s", url);

	const char *model = r_config_get (core->config, "r2ai.model");
	if (R_STR_ISEMPTY (model)) {
		model = "grok-beta";
	}

	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "model", model);
	pj_ka (pj, "messages");
	pj_o (pj);
	pj_ks (pj, "role", "user");
	pj_ka (pj, "parts");
	pj_o (pj);
	pj_ks (pj, "text", content);
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);

	char *data = pj_drain (pj);
	R_LOG_DEBUG ("X.AI API request data: %s", data);
	int code = 0;
	char *res = r_socket_http_post (url, headers, data, &code, NULL);

	free (authorization_bearer);
	if (res) {
		R_LOG_DEBUG ("X.AI API response: %s", res);
	}

	if (!res || code != 200) {
		R_LOG_ERROR ("X.AI API error %d", code);
		if (res) {
			R_LOG_ERROR ("Error response: %s", res);
		}
		if (error) {
			*error = strdup (res? res: "Failed to get response from X.AI API");
		}
		free (apikey);
		free (url);
		free (data);
		return NULL;
	}

	char *saveptr;
	char *line = strtok_r (res, "\n", &saveptr);
	while (line) {
		R_LOG_DEBUG ("Processing chunk: %s", line);
		handle_xai_stream_chunk (line);
		line = strtok_r (NULL, "\n", &saveptr);
	}

	eprintf ("\n");

	free (apikey);
	free (url);
	free (data);
	free (res);
	return NULL;
}
#endif
