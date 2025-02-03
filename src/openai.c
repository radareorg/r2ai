#include <r_core.h>
#include <r_util/r_json.h>

#if R2_VERSION_NUMBER >= 50909

R_IPI char *r2ai_openai(RCore *core, const char *content, const char *model, char **error) {
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
	pj_ks (pj, "model", model? model: "gpt-4o-mini");
	pj_kb (pj, "stream", false);
	pj_kn (pj, "max_completion_tokens", 5128);
	pj_ka (pj, "messages");
	{
		const char *sysprompt = r_config_get (core->config, "r2ai.system");
		if (R_STR_ISNOTEMPTY (sysprompt)) {
			pj_o (pj);
			pj_ks (pj, "role", "system");
			pj_ks (pj, "content", sysprompt);
			pj_end (pj);
		}
	}
	{
		pj_o (pj);
		pj_ks (pj, "role", "user");
		pj_ks (pj, "content", content);
		pj_end (pj);
	}
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
		free (chunk_copy);
	}
	return false;
}

R_IPI char *r2ai_openai_stream(RCore *core, const char *content, const char *model_name, char **error) {
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
	pj_ks (pj, "model", model_name? model_name: "gpt-4o-mini");
	pj_kb (pj, "stream", true);
	pj_kn (pj, "max_completion_tokens", 5128);
	pj_ka (pj, "messages");
	{
		const char *sysprompt = r_config_get (core->config, "r2ai.system");
		if (R_STR_ISNOTEMPTY (sysprompt)) {
			pj_o (pj);
			pj_ks (pj, "role", "system");
			pj_ks (pj, "content", sysprompt);
			pj_end (pj);
		}
	}
	{
		pj_o (pj);
		pj_ks (pj, "role", "user");
		pj_ks (pj, "content", content);
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
	char *data = pj_drain (pj);

	int code = 0;
	char *res = r_socket_http_post (openai_url, headers, data, &code, NULL);
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

#endif
