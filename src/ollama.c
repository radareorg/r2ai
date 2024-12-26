#include "r2ai.h"

R_IPI char *r2ai_ollama(RCore *core, const char *content, const char *model, char **error) {
	if (error) {
		*error = NULL;
	}
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "model", R_STR_ISNOTEMPTY (model)? model: "llama3");
#if 1
	const char *openapi_url = "http://127.0.0.1:11434/api/chat";
	pj_kb (pj, "stream", false);
	pj_ka (pj, "messages");
	const char *sp = r_config_get (core->config, "r2ai.system");
	if (R_STR_ISNOTEMPTY (sp)) {
		pj_o (pj);
		pj_ks (pj, "role", "system");
		pj_ks (pj, "content", sp);
		pj_end (pj);
	}
	pj_o (pj);
		pj_ks (pj, "role", "user");
		pj_ks (pj, "content", content);
	pj_end (pj);
	pj_end (pj);
#else
	const char *openapi_url = "http://127.0.0.1:11434/v1/completions";
	pj_ks (pj, "prompt", content);
	const char *sp = r_config_get (core->config, "r2ai.system");
	if (R_STR_ISNOTEMPTY (sp)) {
		pj_ks (pj, "system", sp);
	}
#endif
#if 0
	pj_ko (pj, "options");
	pj_kn (pj, "temperature", 0);
	pj_end (pj);
#endif
	pj_end (pj);
	char *data = pj_drain (pj);
	int code = 0;
	int rlen = 0;
#if R2_VERSION_NUMBER >= 50909
	const char *headers[] = { "Content-Type: application/json", NULL };
	char *res = r_socket_http_post (openapi_url, headers, data, &code, NULL);
#else
	char *res = r_socket_http_post (openapi_url, data, &code, NULL);
#endif
	free (data);
	if (!res || code != 200) {
		R_LOG_ERROR ("Oops %d", code);
		return NULL;
	}
	char *res_content = NULL;
	RJson *jres = r_json_parse (res);
	if (jres) {
#if 1
		const RJson *jres_choices = r_json_get (jres, "message");
		if (jres_choices) {
			const RJson *jres_content = r_json_get (jres_choices, "content");
			if (jres_content) {
				res_content = strdup (jres_content->str_value);
			}
		}
#else
		const RJson *jres_choices = r_json_get (jres, "choices");
		if (jres_choices) {
			const RJson *jres_choices0 = r_json_item (jres_choices, 0);
			if (jres_choices0) {
				const RJson *jres_message = r_json_get (jres_choices0, "text");
				if (jres_message) {
					res_content = strdup (jres_message->str_value);
				}
			}
		}
#endif
		r_json_free (jres);
	} else {
		R_LOG_ERROR ("%s", res);
	}
	return res_content;
}
