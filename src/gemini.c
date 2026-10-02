/* r2ai - Copyright 2023-2026 pancake, dnakov */

#include "r2ai.h"
#include "r2ai_priv.h"

static void text_parts(PJ *pj, const char *text) {
	pj_ka (pj, "parts");
	pj_o (pj);
	pj_ks (pj, "text", text);
	pj_end (pj);
	pj_end (pj);
}

// request body shared by the gemini and vertex-gemini providers
R_IPI char *r2ai_gemini_request(const R2AIArgs *args) {
	PJ *pj = pj_new ();
	pj_o (pj);
	if (R_STR_ISNOTEMPTY (args->system_prompt)) {
		pj_ko (pj, "systemInstruction");
		text_parts (pj, args->system_prompt);
		pj_end (pj);
	}
	pj_ka (pj, "contents");
	RListIter *iter;
	R2AI_Message *msg;
	r_list_foreach (args->messages, iter, msg) {
		pj_o (pj);
		pj_ks (pj, "role", strcmp (msg->role, "assistant")? "user": "model");
		text_parts (pj, r_str_get (msg->content));
		pj_end (pj);
	}
	pj_end (pj);
	pj_ko (pj, "generationConfig");
	if (args->max_tokens > 0) {
		pj_kn (pj, "maxOutputTokens", args->max_tokens);
	}
	if (args->temperature > 0) {
		pj_kd (pj, "temperature", args->temperature);
	}
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

// parses (and modifies) the json response of the gemini and vertex-gemini providers
R_IPI R2AI_ChatResponse *r2ai_gemini_parse(char *json, char **error) {
	RJson *j = r_json_parse (json);
	if (!j) {
		*error = strdup ("Failed to parse Gemini response JSON");
		return NULL;
	}
	const RJson *c = r_json_get (j, "candidates");
	c = c? r_json_item (c, 0): NULL;
	c = c? r_json_get (c, "content"): NULL;
	c = c? r_json_get (c, "parts"): NULL;
	c = c? r_json_item (c, 0): NULL;
	const char *text = c? r_json_get_str (c, "text"): NULL;
	if (!text) {
		r_json_free (j);
		return NULL;
	}
	R2AI_Usage *usage = R_NEW0 (R2AI_Usage);
	const RJson *u = r_json_get (j, "usageMetadata");
	if (u) {
		usage->prompt_tokens = r_json_get_num (u, "promptTokenCount");
		usage->completion_tokens = r_json_get_num (u, "candidatesTokenCount");
		usage->total_tokens = r_json_get_num (u, "totalTokenCount");
	}
	R2AI_Message *message = R_NEW0 (R2AI_Message);
	message->role = strdup ("assistant");
	message->content = strdup (text);
	r_json_free (j);
	R2AI_ChatResponse *res = R_NEW0 (R2AI_ChatResponse);
	res->message = message;
	res->usage = usage;
	return res;
}

R_IPI R2AI_ChatResponse *r2ai_gemini(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;
	const char *model = strstr (args.model, "gemini")? args.model: "gemini-2.0-flash-exp";
	char *base_url = r2ai_get_provider_url (core, args.provider);
	char *url = r_str_newf ("%s/models/%s:generateContent", base_url, model);
	free (base_url);
	// OAuth tokens start with "ya29.", the key travels in the headers and never in the url
	const bool oauth = r_str_startswith (args.api_key, "ya29.");
	char *auth = r_str_newf (oauth? "Authorization: Bearer %s": "x-goog-api-key: %s", args.api_key);
	const char *headers[] = { "Content-Type: application/json", auth, NULL };
	char *data = r2ai_gemini_request (&args);
	int code = 0;
	char *res = r2ai_post (core, "gemini", url, headers, data, &code, args.error);
	free (data);
	free (url);
	free (auth);
	R2AI_ChatResponse *result = res? r2ai_gemini_parse (res, args.error): NULL;
	free (res);
	return result;
}
