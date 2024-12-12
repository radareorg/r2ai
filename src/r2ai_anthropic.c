#include <r_core.h>
#include <r_util/r_json.h>

static bool handle_anthropic_stream_chunk(const char *chunk) {
	if (R_STR_ISEMPTY (chunk)) {
		return false;
	}

	if (r_str_startswith (chunk, "event:")) {
		const char *event = chunk + 7;
		while (*event == ' ') {
			event++;
		}
		return !strcmp (event, "message_stop");
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

	const RJson *type = r_json_get (jres, "type");
	if (!type || !type->str_value) {
		r_json_free (jres);
		free (data_copy);
		return false;
	}

	if (!strcmp(type->str_value, "content_block_delta")) {
		const RJson *delta = r_json_get (jres, "delta");
		if (delta) {
			const RJson *text = r_json_get(delta, "text");
			if (text && text->str_value) {
				eprintf ("%s", text->str_value);
			}
		}
	}

	r_json_free (jres);
	free (data_copy);
	return false;
}

static char *r2ai_anthropic(const char *content, const char *model_name, char **error) {
	if (error) {
		*error = NULL;
	}

	char *apikey = r_sys_getenv ("ANTHROPIC_API_KEY");
	if (!apikey) {
		char *apikey_file = r_file_new ("~/.r2ai.anthropic-key", NULL);
		apikey = r_file_slurp (apikey_file, NULL);
		free (apikey_file);
		if (!apikey) {
			if (error) {
				*error = strdup ("Failed to read Anthropic API key from ANTHROPIC_API_KEY env or ~/.r2ai.anthropic-key");
			}
			return NULL;
		}
		r_str_trim (apikey);
	}

	char *auth_header = r_str_newf ("x-api-key: %s", apikey);
	char *anthropic_version = "anthropic-version: 2023-06-01";
	const char *headers[] = {
		"Content-Type: application/json",
		auth_header,
		anthropic_version,
		NULL
	};

	const char *anthropic_url = "https://api.anthropic.com/v1/messages";

	PJ *pj = pj_new ();
	pj_o(pj);
	pj_ks(pj, "model", model_name);
	pj_kn(pj, "max_tokens", 4096);
	pj_ka(pj, "messages");
	pj_o(pj);
	pj_ks(pj, "role", "user"); 
	pj_ks(pj, "content", content);
	pj_end(pj);
	pj_end(pj);
	pj_end(pj);

	char *data = pj_drain (pj);
	int code = 0;
	char *res = r_socket_http_post (anthropic_url, headers, data, &code, NULL);
	if (!res || code != 200) {
		R_LOG_ERROR ("Anthropic API error %d", code);
		if (error) {
			*error = strdup (res? res : "Failed to get response from Anthropic API");
		}
		free (apikey);
		free (auth_header);
		free (data);
		free (res);
		return NULL;
	}

	char *res_content = NULL;
	RJson *jres = r_json_parse (res);
	if (jres) {
		const RJson *content_array = r_json_get (jres, "content");
		if (content_array && content_array->type == R_JSON_ARRAY) {
			const RJson *first_content = r_json_item (content_array, 0);
			if (first_content) {
				const RJson *text = r_json_get (first_content, "text");
				if (text) {
					res_content = strdup (text->str_value);
				}
			}
		}
		r_json_free (jres);
	}
	free (apikey);
	free (auth_header); 
	free (data);
	free (res);
	return res_content;
}

static char *r2ai_anthropic_stream(const char *content, const char *model_name, char **error) {
	if (error) {
		*error = NULL;
	}
	char *apikey = r_sys_getenv ("ANTHROPIC_API_KEY");
	if (!apikey) {
		char *apikey_file = r_file_new ("~/.r2ai.anthropic-key", NULL);
		apikey = r_file_slurp (apikey_file, NULL);
		free(apikey_file);
		if (!apikey) {
			if (error) {
				*error = strdup ("Failed to read Anthropic API key from ANTHROPIC_API_KEY env or ~/.r2ai.anthropic-key");
			}
			return NULL;
		}
		r_str_trim (apikey);
	}

	char *auth_header = r_str_newf ("x-api-key: %s", apikey);
	char *anthropic_version = "anthropic-version: 2023-06-01";
	char *accept_header = "Accept: text/event-stream";
	const char *headers[] = {
		"Content-Type: application/json",
		auth_header,
		anthropic_version,
		accept_header,
		NULL
	};

	const char anthropic_url[] = "https://api.anthropic.com/v1/messages";

	PJ *pj = pj_new ();
	pj_o(pj);
	pj_ks(pj, "model", model_name? model_name: "claude-3-5-sonnet-20241022");
	pj_kn(pj, "max_tokens", 4096);
	pj_kb(pj, "stream", true);
	pj_ka(pj, "messages");
	pj_o(pj);
	pj_ks(pj, "role", "user");
	pj_ks(pj, "content", content);
	pj_end(pj);
	pj_end(pj);
	pj_end(pj);

	char *data = pj_drain(pj);
	int code = 0;
	char *res = r_socket_http_post (anthropic_url, headers, data, &code, NULL);
	
	if (!res || code != 200) {
		R_LOG_ERROR ("Anthropic API error %d", code);
		if (error) {
			*error = strdup ("Failed to get response from Anthropic API");
		}
		free (apikey);
		free (auth_header);
		free (data);
		return NULL;
	}

	char *saveptr;
	char *line = strtok_r (res, "\n", &saveptr);
	while (line) {
		handle_anthropic_stream_chunk (line);
		line = strtok_r (NULL, "\n", &saveptr);
	}

	eprintf ("\n");

	free (apikey);
	free (auth_header);
	free (data);
	free (res);

	return NULL;
}