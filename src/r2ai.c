/* radare - Copyright 2023-2024 pancake */

#define R_LOG_ORIGIN "r2ai"

#include <r_core.h>
#include <r_util/r_json.h>

static char *r2ai_openai(const char *content, char **error) {
	if (error) {
		*error = NULL;
	}
	char *apikey_file = r_file_new ("~/.r2ai.openai-key", NULL);
	char *apikey = r_file_slurp (apikey_file, NULL);
	free (apikey_file);
	if (!apikey) {
		if (error) {
			*error = strdup ("Failed to read OpenAI API key from ~/.r2ai.openai-key");
		}
		return NULL;
	}
	r_str_trim (apikey);
	char *auth_header = r_str_newf ("Authorization: Bearer %s", apikey);
	const char *headers[] = { "Content-Type: application/json", auth_header, NULL };
	const char *openai_url = "https://api.openai.com/v1/chat/completions";
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "model", "gpt-4o-mini");
	pj_kb (pj, "stream", true);
	pj_kn (pj, "max_completion_tokens", 5128);
	pj_ka (pj, "messages");
	pj_o (pj);
	pj_ks (pj, "role", "user");
	pj_ks (pj, "content", content);
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);
	char *data = pj_drain (pj);
	int code = 0;
	char *res = r_socket_http_post (openai_url, headers, data, &code, NULL);
	if (code != 200) {
		R_LOG_ERROR ("Oops %d", code);
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
	free (auth_header);
	free (data);
	free (res);
	return res_content;
}

static bool handle_openai_stream_chunk(const char *chunk) {
	if (!chunk) {
		return false;
	}

	if (!strcmp (chunk, "data: [DONE]")) {
		return true;
	}
	if (r_str_startswith (chunk, "data: ")) {
		chunk += 6;
		char *chunk_copy = strdup(chunk);
		RJson *jres = r_json_parse (chunk_copy);
		if (jres) {
			const RJson *choices = r_json_get (jres, "choices");
			if (choices) {
				const RJson *choice = r_json_item (choices, 0);
				if (choice) {
					const RJson *delta = r_json_get (choice, "delta");
					if (delta) {
						const RJson *content = r_json_get (delta, "content");
						if (content && content->str_value) {
							r_cons_print (content->str_value);
							r_cons_flush ();
						}
					}
				}
			}
			r_json_free (jres);
		}
		free(chunk_copy);
	}
	return false;
}

static char *r2ai_openai_stream(const char *content, char **error) {
	if (error) {
		*error = NULL;
	}
	char *apikey = r_sys_getenv ("OPENAI_API_KEY");

	if (!apikey) {
		char *apikey_file = r_file_new ("~/.r2ai.openai-key", NULL);
		apikey = r_file_slurp (apikey_file, NULL);
		free (apikey_file);
		if (!apikey) {
			if (error) {
				*error = strdup ("Failed to read OpenAI API key from OPENAI_API_KEY env or ~/.r2ai.openai-key");
			}
			return NULL;
		}
		r_str_trim (apikey);
	}
	char *auth_header = r_str_newf ("Authorization: Bearer %s", apikey);
	const char *headers[] = { "Content-Type: application/json", auth_header, NULL };
	const char *openai_url = "https://api.openai.com/v1/chat/completions";
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "model", "gpt-4o-mini");
	pj_kb (pj, "stream", true);
	pj_kn (pj, "max_completion_tokens", 5128);
	pj_ka (pj, "messages");
	pj_o (pj);
	pj_ks (pj, "role", "user");
	pj_ks (pj, "content", content);
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);
	char *data = pj_drain (pj);

	int code = 0;
	int rlen = 0;
	char *res = r_socket_http_post (openai_url, headers,data, &code, NULL);
	if (!res || code != 200) {
		R_LOG_ERROR ("Oops %d", code);
		return NULL;
	}
	char *line = res;
	while (line) {
		char *eol = strchr (line, '\n');
		if (eol) {
			*eol = 0;
			handle_openai_stream_chunk (line);
			line = eol + 1;
		} else {
			handle_openai_stream_chunk (line);
			break;
		}
	}
	free (apikey);
	free (auth_header);
	free (data);
	free (res);
	return NULL;
}

static char *r2ai_openapi(const char *content, char **error) {
	if (error) {
		*error = NULL;
	}
	const char *headers[] = { "Content-Type: application/json", NULL };
	// const char *openapi_url = "http://127.0.0.1:8080/api/generate";
	const char *openapi_url = "http://127.0.0.1:8080/completion";
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "prompt", content);
	pj_end (pj);
	char *data = pj_drain (pj);
	int code = 0;
	int rlen = 0;
	char *res = r_socket_http_post (openapi_url, headers, data, &code, NULL);
	if (!res || code != 200) {
		R_LOG_ERROR ("Oops %d", code);
		return NULL;
	}
	char *res_content = NULL;
	RJson *jres = r_json_parse (res);
	if (jres) {
		const RJson *jres_response = r_json_get (jres, "response");
		if (jres_response) {
			res_content = strdup (jres_response->str_value);
		} else {
			const RJson *jres_response = r_json_get (jres, "content");
			if (jres_response) {
				res_content = strdup (jres_response->str_value);
			}
		}
		r_json_free (jres);
	} else {
		R_LOG_ERROR ("%s", res);
	}
	return res_content;
}

static bool handle_anthropic_stream_chunk(const char *chunk) {
	if (!chunk || !*chunk) {
		return false;
	}

	if (r_str_startswith(chunk, "event:")) {
		const char *event = chunk + 7;
		while (*event == ' ') event++;
		return !strcmp(event, "message_stop");
	}
	
	if (!r_str_startswith(chunk, "data:")) {
		return false;
	}

	const char *data = chunk + 6;
	while (*data == ' ') data++;
	if (!*data) {
		return false;
	}

	char *data_copy = strdup(data);
	RJson *jres = r_json_parse(data_copy);
	if (!jres) {
		free(data_copy);
		return false;
	}

	const RJson *type = r_json_get(jres, "type");
	if (!type || !type->str_value) {
		r_json_free(jres);
		free(data_copy);
		return false;
	}

	if (!strcmp(type->str_value, "content_block_delta")) {
		const RJson *delta = r_json_get(jres, "delta");
		if (delta) {
			const RJson *text = r_json_get(delta, "text");
			if (text && text->str_value) {
				eprintf("%s", text->str_value);
			}
		}
	}

	r_json_free(jres);
	free(data_copy);
	return false;
}

static bool handle_anthropic_chunk_cb(void *user, const char *chunk, int len) {
	if (!chunk || len <= 0) {
		return false;
	}
	
	char *chunk_copy = malloc(len + 1);
	memcpy(chunk_copy, chunk, len);
	chunk_copy[len] = 0;

	char *line = chunk_copy;
	while (line) {
		char *eol = strchr(line, '\n');
		if (eol) {
			*eol = 0;
			handle_anthropic_stream_chunk(line);
			line = eol + 1;
		} else {
			if (*line) {
				handle_anthropic_stream_chunk(line);
			}
			break;
		}
	}

	free(chunk_copy);
	return true;
}

static char *r2ai_anthropic_stream(const char *content, const char *model_name, char **error) {
	if (error) {
		*error = NULL;
	}
	char *apikey = r_sys_getenv("ANTHROPIC_API_KEY");
	if (!apikey) {
		char *apikey_file = r_file_new("~/.r2ai.anthropic-key", NULL);
		apikey = r_file_slurp(apikey_file, NULL);
		free(apikey_file);
		if (!apikey) {
			if (error) {
				*error = strdup("Failed to read Anthropic API key from ANTHROPIC_API_KEY env or ~/.r2ai.anthropic-key");
			}
			return NULL;
		}
		r_str_trim(apikey);
	}

	char *auth_header = r_str_newf("x-api-key: %s", apikey);
	char *anthropic_version = "anthropic-version: 2023-06-01";
	char *accept_header = "Accept: text/event-stream";
	const char *headers[] = {
		"Content-Type: application/json",
		auth_header,
		anthropic_version,
		accept_header,
		NULL
	};

	const char *anthropic_url = "https://api.anthropic.com/v1/messages";

	PJ *pj = pj_new();
	pj_o(pj);
	pj_ks(pj, "model", model_name);
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
	char *res = r_socket_http_post(anthropic_url, headers, data, &code, NULL);
	
	if (!res || code != 200) {
		R_LOG_ERROR("Anthropic API error %d", code);
		if (error) {
			*error = strdup("Failed to get response from Anthropic API");
		}
		free(apikey);
		free(auth_header);
		free(data);
		return NULL;
	}

	char *saveptr;
	char *line = strtok_r(res, "\n", &saveptr);
	while (line) {
		handle_anthropic_stream_chunk(line);
		line = strtok_r(NULL, "\n", &saveptr);
	}

	eprintf("\n");

	free(apikey);
	free(auth_header);
	free(data);
	free(res);

	return NULL;
}

static char *r2ai_anthropic(const char *content, const char *model_name, char **error) {
	if (error) {
		*error = NULL;
	}

	char *apikey = r_sys_getenv("ANTHROPIC_API_KEY");
	if (!apikey) {
		char *apikey_file = r_file_new("~/.r2ai.anthropic-key", NULL);
		apikey = r_file_slurp(apikey_file, NULL);
		free(apikey_file);
		if (!apikey) {
			if (error) {
				*error = strdup("Failed to read Anthropic API key from ANTHROPIC_API_KEY env or ~/.r2ai.anthropic-key");
			}
			return NULL;
		}
		r_str_trim(apikey);
	}

	char *auth_header = r_str_newf("x-api-key: %s", apikey);
	char *anthropic_version = "anthropic-version: 2023-06-01";
	const char *headers[] = {
		"Content-Type: application/json",
		auth_header,
		anthropic_version,
		NULL
	};

	const char *anthropic_url = "https://api.anthropic.com/v1/messages";

	PJ *pj = pj_new();
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

	char *data = pj_drain(pj);
	int code = 0;
	char *res = r_socket_http_post(anthropic_url, headers, data, &code, NULL);
	if (!res || code != 200) {
		R_LOG_ERROR("Anthropic API error %d", code);
		if (error) {
			*error = strdup(res ? res : "Failed to get response from Anthropic API");
		}
		free(apikey);
		free(auth_header);
		
		free(data);
		free(res);
		return NULL;
	}

	char *res_content = NULL;
	RJson *jres = r_json_parse(res);
	if (jres) {
		const RJson *content_array = r_json_get(jres, "content");
		if (content_array && content_array->type == R_JSON_ARRAY) {
			const RJson *first_content = r_json_item(content_array, 0);
			if (first_content) {
				const RJson *text = r_json_get(first_content, "text");
				if (text) {
					res_content = strdup(text->str_value);
				}
			}
		}
		r_json_free(jres);
	}

	free(apikey);
	free(auth_header); 
	free(data);
	free(res);
	return res_content;
}

static char *r2ai(RCore *core, const char *content, char **error) {
	if (R_STR_ISEMPTY (content)) {
		*error = strdup ("Usage: 'r2ai [query]'. See 'r2ai -h' for help");
		return NULL;
	}
	const char *model = r_config_get (core->config, "r2ai.model");
	if (!model) {
		*error = strdup ("Model not configured. Use 'r2ai -m provider:model' to set it");
		return NULL;
	}

	char *provider = strdup (model);
	char *model_name = strchr (provider, ':');
	if (!model_name) {
		free (provider);
		*error = strdup ("Invalid model format. Use 'provider:model_name'");
		return NULL;
	}
	*model_name = 0;
	model_name++;
	
	bool stream = r_config_get_i (core->config, "r2ai.stream");
	char *result = NULL;
	if (!strcmp (provider, "openai")) {
		result = stream? r2ai_openai_stream (content, error) : r2ai_openai (content, error);
	} else if (!strcmp (provider, "openapi")) {
		result = r2ai_openapi (content, error);
	} else if (!strcmp (provider, "anthropic")) {
		result = stream? r2ai_anthropic_stream(content, model_name, error) : 
		               r2ai_anthropic(content, model_name, error);
	} else {
		*error = strdup ("Unsupported provider");
	}
	
	free (provider);
	return result;
}

static void cmd_r2ai_m(RCore *core, const char *input) {
	r_config_lock (core->config, false);
	r_config_set (core->config, "r2ai.model", input);
	r_config_lock (core->config, true);
	r_cons_printf ("Model set to %s\n", input);
}

static void cmd_r2ai(RCore *core, const char *input) {
	if (r_str_startswith (input, "-m")) {
		cmd_r2ai_m (core, r_str_trim_head_ro (input + 2));
	} else {
		char *err = NULL;
		char *res = r2ai (core, input, &err);
		if (err) {
			R_LOG_ERROR ("%s", err);
			R_FREE (err);
		}
		if (res) {
			r_cons_printf ("%s\n", res);
			free (res);
		}
	}
}

static int r_cmd_r2ai_client(void *user, const char *input) {
	RCore *core = (RCore *) user;
	static RCoreHelpMessage help_msg_a2f = {
		"Usage:", "r2ai", "Use POST http://localhost:8000",
		"r2ai", "-m", "show selected model, list suggested ones, choose one"
		"r2ai", " [arg]", "send a post request to talk to r2ai and print the output",
		NULL
	};
	r_config_lock (core->config, false);
	r_config_set (core->config, "r2ai.api", "openapi");
	// r_config_set (core->config, "r2ai.model", "qwen2.5-4km");
	r_config_set_i (core->config, "r2ai.stream", true);
	r_config_lock (core->config, true);
	r_sys_setenv ("R2_CURL", "1");
	if (r_str_startswith (input, "r2ai")) {
		cmd_r2ai (core, r_str_trim_head_ro (input + 4));
		return true;
	}
	return false;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_r2ai_client = {
	.meta = {
		.name = "r2ai-client",
		.desc = "remote r2ai client using http post",
		.author = "pancake",
		.license = "MIT",
	},
	.call = r_cmd_r2ai_client,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_r2ai_client,
	.version = R2_VERSION
};
#endif
