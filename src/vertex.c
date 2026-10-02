/* Copyright r2ai - 2023-2026 - pancake */

#include "r2ai.h"
#include "r2ai_priv.h"

#define R2AI_VERTEX_TOKEN_TTL_US (3300ULL * R_USEC_PER_SEC) /* 55 minutes, tokens are valid for ~60 */

static char *vertex_fetch_token(void) {
	char *version = r_sys_cmd_str ("gcloud version", NULL, NULL);
	if (R_STR_ISEMPTY (version)) {
		free (version);
		R_LOG_ERROR ("gcloud CLI not found. Install it from https://cloud.google.com/sdk/docs/install");
		return NULL;
	}
	free (version);
	char *token = r_sys_cmd_str ("gcloud auth application-default print-access-token", NULL, NULL);
	if (R_STR_ISEMPTY (token)) {
		free (token);
		R_LOG_ERROR ("gcloud is not authenticated. Run 'gcloud auth application-default login'");
		return NULL;
	}
	r_str_trim (token);
	if (R_STR_ISEMPTY (token)) {
		free (token);
		return NULL;
	}
	return token;
}

/* The returned pointer is owned by state and must NOT be freed by the caller */
R_IPI const char *r2ai_vertex_get_token(R2AI_State *state) {
	ut64 now = r_time_now_mono ();
	if (state->vertex_token && now < state->vertex_token_expiry) {
		return state->vertex_token;
	}
	free (state->vertex_token);
	state->vertex_token = vertex_fetch_token ();
	state->vertex_token_expiry = state->vertex_token? now + R2AI_VERTEX_TOKEN_TTL_US: 0;
	return state->vertex_token;
}

// returns the publisher endpoint url or NULL when the cloud project or region are not set
static char *vertex_url(const char *publisher, const char *model, const char *method, char **error) {
	char *project = r_sys_getenv ("GOOGLE_CLOUD_PROJECT");
	char *region = r_sys_getenv ("GOOGLE_CLOUD_REGION");
	char *url = NULL;
	if (R_STR_ISNOTEMPTY (project) && R_STR_ISNOTEMPTY (region)) {
		url = r_str_newf ("https://%s-aiplatform.googleapis.com/v1/projects/%s/locations/%s/publishers/%s/models/%s:%s",
			region, project, region, publisher, model, method);
	} else {
		*error = strdup ("Set GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_REGION env vars first");
	}
	free (project);
	free (region);
	return url;
}

static char *vertex_post(RCorePluginSession *cps, R2AIArgs *args, const char *name, const char *publisher, const char *method, const char *data) {
	char *url = vertex_url (publisher, args->model, method, args->error);
	if (!url) {
		return NULL;
	}
	char *auth = r_str_newf ("Authorization: Bearer %s", args->api_key);
	const char *headers[] = { "Content-Type: application/json", auth, NULL };
	int code = 0;
	char *res = r2ai_post (cps->core, name, url, headers, data, &code, args->error);
	free (auth);
	free (url);
	return res;
}

R_IPI R2AI_ChatResponse *r2ai_vertex_gemini(RCorePluginSession *cps, R2AIArgs args) {
	char *data = r2ai_gemini_request (&args);
	char *res = vertex_post (cps, &args, "vertex_gemini", "google", "generateContent", data);
	free (data);
	R2AI_ChatResponse *result = res? r2ai_gemini_parse (res, args.error): NULL;
	free (res);
	return result;
}

R_IPI R2AI_ChatResponse *r2ai_vertex_anthropic(RCorePluginSession *cps, R2AIArgs args) {
	char *data = r2ai_anthropic_request (&args, true);
	if (!data) {
		*args.error = strdup ("No input or messages provided");
		return NULL;
	}
	char *res = vertex_post (cps, &args, "vertex_anthropic", "anthropic", "rawPredict", data);
	free (data);
	R2AI_ChatResponse *result = res? r2ai_anthropic_parse_response (res, args.error): NULL;
	free (res);
	return result;
}
