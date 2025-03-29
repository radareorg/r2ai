#include "r2ai.h"

#if R2_VERSION_NUMBER >= 50909

static bool handle_gemini_stream_chunk (const char *chunk) {
	if (R_STR_ISEMPTY (chunk)) {
		return false;
	}

	if (!r_str_startswith (chunk, "data:")) {
		return false;
	}

	const char *data = chunk + 6;
	while (*data == ' ') {
		data++;
	}
	if (!*data) {
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

R_IPI char *r2ai_gemini (RCore *core, R2AIArgs args) {
	const char *content = args.input;
	const char *model = args.model;
	char **error = args.error;

	char *result = NULL;
	char *api_key = r_config_get (core->config, "r2ai.gemini.api_key");
	if (!api_key) {
		*error = strdup ("Gemini API key not found. Set r2ai.gemini.api_key");
		return NULL;
	}

	if (!content) {
		*error = strdup ("Content cannot be null");
		return NULL;
	}

	if (error) {
		*error = NULL;
	}

	char *url = r_str_newf ("%s/%s:generateContent?key=%s",
		"https://generativelanguage.googleapis.com/v1beta/models",
		model ? model : "gemini-1.5-pro",
		api_key);

	R_LOG_DEBUG ("Gemini API URL: %s", url);

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
	R_LOG_DEBUG ("Gemini API request data: %s", data);
	int code = 0;
	char *res = r_socket_http_post (url, NULL, data, &code, NULL);

	if (res) {
		R_LOG_DEBUG ("Gemini API response: %s", res);
	}

	if (!res || code != 200) {
		R_LOG_ERROR ("Gemini API error %d", code);
		if (res) {
			R_LOG_ERROR ("Error response: %s", res);
		}
		if (error) {
			*error = strdup (res ? res : "Failed to get response from Gemini API");
		}
		free (api_key);
		free (url);
		free (data);
		free (res);
		return NULL;
	}

	char *res_content = NULL;
	RJson *jres = r_json_parse (res);
	if (jres) {
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
							if (text) {
								res_content = strdup (text->str_value);
								eprintf ("%s\n", text->str_value);
							}
						}
					}
				}
			}
		}
		r_json_free (jres);
	}

	free (api_key);
	free (url);
	free (data);
	free (res);
	return res_content;
}

R_IPI char *r2ai_gemini_stream (RCore *core, R2AIArgs args) {
	const char *content = args.input;
	const char *model = args.model;
	char **error = args.error;

	char *result = NULL;
	char *api_key = r_config_get (core->config, "r2ai.gemini.api_key");
	if (!api_key) {
		*error = strdup ("Gemini API key not found. Set r2ai.gemini.api_key");
		return NULL;
	}

	if (!content) {
		*error = strdup ("Content cannot be null");
		return NULL;
	}

	if (error) {
		*error = NULL;
	}

	char *url = r_str_newf ("%s/%s:streamGenerateContent?alt=sse&key=%s",
		"https://generativelanguage.googleapis.com/v1beta/models",
		model ? model : "gemini-1.5-pro",
		api_key);

	R_LOG_DEBUG ("Gemini API URL: %s", url);

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
	R_LOG_DEBUG ("Gemini API request data: %s", data);
	int code = 0;
	char *res = r_socket_http_post (url, NULL, data, &code, NULL);

	if (res) {
		R_LOG_DEBUG ("Gemini API response: %s", res);
	}

	if (!res || code != 200) {
		R_LOG_ERROR ("Gemini API error %d", code);
		if (res) {
			R_LOG_ERROR ("Error response: %s", res);
		}
		if (error) {
			*error = strdup (res ? res : "Failed to get response from Gemini API");
		}
		free (api_key);
		free (url);
		free (data);
		return NULL;
	}

	char *saveptr;
	char *line = strtok_r (res, "\n", &saveptr);
	while (line) {
		R_LOG_DEBUG ("Processing chunk: %s", line);
		handle_gemini_stream_chunk (line);
		line = strtok_r (NULL, "\n", &saveptr);
	}

	eprintf ("\n");

	free (api_key);
	free (url);
	free (data);
	free (res);
	return NULL;
}
#endif
