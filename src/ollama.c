#include "r2ai.h"

R_IPI char *r2ai_ollama(const char *content, const char *model, char **error) {
	if (error) {
		*error = NULL;
	}
	const char *openapi_url = "http://127.0.0.1:11434/v1/completions";
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "model", R_STR_ISNOTEMPTY (model)? model: "llama3");
	pj_ks (pj, "prompt", content);
	// pj_kn (pj, "n_predict", 128);
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
	if (!res || code != 200) {
		R_LOG_ERROR ("Oops %d", code);
		return NULL;
	}
	char *res_content = NULL;
	RJson *jres = r_json_parse (res);
	if (jres) {
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
		r_json_free (jres);
	} else {
		R_LOG_ERROR ("%s", res);
	}
	return res_content;
}
