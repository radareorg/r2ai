/* radare - Copyright 2023-2024 pancake */

#define R_LOG_ORIGIN "r2ai"

#include <r_core.h>
#include <r_util/r_json.h>

static char *r2ai_openai(const char *content, char **error) {
	if (error) {
		*error = NULL;
	}
	char *apikey = r_file_slurp ("/Users/pancake/.r2ai.openai-key", NULL);
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
}

static int r_cmd_r2ai_client(void *user, const char *input) {
	RCore *core = (RCore *) user;
	static RCoreHelpMessage help_msg_a2f = {
		"Usage:", "r2ai", "Use POST http://localhost:8000",
		"r2ai", " [arg]", "send a post request to talk to r2ai and print the output",
		NULL
	};
	r_sys_setenv ("R2_CURL", "1");
	if (r_str_startswith (input, "r2ai")) {
		const char *content = r_str_trim_head_ro (input + 4);
		char *err;
		char *res = r2ai_openai (content, &err);
		r_cons_printf ("%s\n", res);
		free (res);
		// free (content);
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
