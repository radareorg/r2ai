#include "r2ai.h"

static char *prompt_for_llama(const char* s) {
	const char *sysprompt = "<s><<SYS>>You are a helpful assistant named r2clippy. Respond few words<</SYS>></s>";
	return r_str_newf ("%s<s>[INST]%s[/INST]", sysprompt, s);
}

R_IPI char *r2ai_openapi(const char *content, char **error) {
	if (error) {
		*error = NULL;
	}
	// const char *openapi_url = "http://127.0.0.1:8080/api/generate";
	// const char *openapi_url = "http://127.0.0.1:8080/completion";
	const char *openapi_url = "http://127.0.0.1:11434/completion";
	PJ *pj = pj_new ();
	pj_o (pj);
	char *msg = prompt_for_llama (content);
	pj_ks (pj, "prompt", msg);
	// pj_kn (pj, "n_predict", 128);
	free (msg);
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
