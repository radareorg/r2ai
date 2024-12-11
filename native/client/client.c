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
	r_str_trim (apikey);
	char *auth_header = r_str_newf ("Authorization: Bearer %s", apikey);
	const char *headers[] = { "Content-Type: application/json", auth_header, NULL };
	const char *openai_url = "https://api.openai.com/v1/chat/completions";
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "model", "gpt-4");
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
	// eprintf ("--> (%s)\n", data);
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
	return res_content;
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
	// eprintf ("--> (%s)\n", data);
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

static char *r2ai(RCore *core, const char *content, char **error) {
	if (R_STR_ISEMPTY (content)) {
		*error = strdup ("Usage: 'r2ai [query]'. See 'r2ai -h' for help");
		return NULL;
	}
	const char *api = r_config_get (core->config, "r2ai.api");
	if (api) {
	       if (!strcmp (api, "openai")) {
			return r2ai_openai (content, error);
	       }
	}
	return r2ai_openapi (content, error);
}

static void cmd_r2ai_m(RCore *core, const char *input) {
	r_cons_printf ("https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF/resolve/main/qwen2.5-coder-7b-instruct-q4_k_m.gguf\n");
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
	r_config_set (core->config, "r2ai.model", "qwen2.5-4km");
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
