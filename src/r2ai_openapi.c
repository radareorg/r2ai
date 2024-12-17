#include "r2ai.h"

R_IPI char *r2ai_openapi(const char *content, char **error) {
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
