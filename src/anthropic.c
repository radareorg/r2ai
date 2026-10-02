/* Copyright r2ai - 2023-2026 - pancake */

#include "r2ai.h"
#include "r2ai_priv.h"

// request body, vertex takes the api version in the body and the model in the url
R_IPI char *r2ai_anthropic_request(const R2AIArgs *args, bool vertex) {
	char *messages = r_list_empty (args->messages)? NULL: r2ai_msgs_to_anthropic_json (args->messages);
	if (!messages) {
		return NULL;
	}
	PJ *pj = pj_new ();
	pj_o (pj);
	if (vertex) {
		pj_ks (pj, "anthropic_version", "vertex-2023-10-16");
		pj_kb (pj, "stream", false);
	} else {
		pj_ks (pj, "model", R_STR_ISNOTEMPTY (args->model)? args->model: "claude-3-7-sonnet-20250219");
	}
	pj_kn (pj, "max_tokens", args->max_tokens? args->max_tokens: 4096);
	if (args->thinking_tokens >= 1024) {
		pj_ko (pj, "thinking");
		pj_ks (pj, "type", "enabled");
		pj_kn (pj, "budget_tokens", args->thinking_tokens);
		pj_end (pj);
	} else if (args->deterministic) {
		// top_p is not sent because newer models reject it along with temperature
		pj_kn (pj, "temperature", 0);
		pj_kn (pj, "top_k", 1);
	}
	if (R_STR_ISNOTEMPTY (args->system_prompt)) {
		pj_ks (pj, "system", args->system_prompt);
	}
	pj_k (pj, "messages");
	pj_raw (pj, messages);
	free (messages);
	char *tools = r_list_empty (args->tools)? NULL: r2ai_tools_to_anthropic_json (args->tools);
	if (tools) {
		pj_k (pj, "tools");
		pj_raw (pj, tools);
		free (tools);
	}
	pj_end (pj);
	return pj_drain (pj);
}

R_IPI R2AI_ChatResponse *r2ai_anthropic(RCorePluginSession *cps, R2AIArgs args) {
	char *data = r2ai_anthropic_request (&args, false);
	if (!data) {
		*args.error = strdup ("No input or messages provided");
		return NULL;
	}
	char *auth = r_str_newf ("x-api-key: %s", args.api_key);
	const char *headers[] = { "Content-Type: application/json", auth, "anthropic-version: 2023-06-01", NULL };
	int code = 0;
	char *res = r2ai_post (cps->core, "anthropic", "https://api.anthropic.com/v1/messages", headers, data, &code, args.error);
	free (data);
	free (auth);
	R2AI_ChatResponse *result = res? r2ai_anthropic_parse_response (res, args.error): NULL;
	free (res);
	return result;
}

static char *jstr(const RJson *j, const char *key) {
	return r_str_new (r_json_get_str (j, key));
}

// fill the block from the content item and append its text to the message content
static void parse_block(R2AI_ContentBlock *b, const RJson *item, R2AI_Message *msg, RStrBuf *sb) {
	if (!strcmp (b->type, "text")) {
		b->text = jstr (item, "text");
		r_strbuf_append (sb, r_str_get (b->text));
	} else if (!strcmp (b->type, "tool_use")) {
		const RJson *input = r_json_get (item, "input");
		b->id = jstr (item, "id");
		b->name = jstr (item, "name");
		b->input = (input && input->type == R_JSON_OBJECT)? r_json_to_string (input): NULL;
		R2AI_ToolCall *tc = R_NEW0 (R2AI_ToolCall);
		tc->id = r_str_new (b->id);
		tc->name = r_str_new (b->name);
		tc->arguments = r_str_new (b->input);
		if (!msg->tool_calls) {
			msg->tool_calls = r_list_newf ((RListFree)r2ai_tool_call_free);
		}
		r_list_append (msg->tool_calls, tc);
	} else if (!strcmp (b->type, "thinking")) {
		b->data = jstr (item, "data");
		b->thinking = jstr (item, "thinking");
		b->signature = jstr (item, "signature");
		r_strbuf_appendf (sb, "\n" Color_GRAY "<thinking>\n%s\n</thinking>" Color_RESET "\n", r_str_get (b->thinking));
	}
}

// parses (and modifies) the json response of the anthropic and vertex-anthropic providers
R_IPI R2AI_ChatResponse *r2ai_anthropic_parse_response(char *json, char **error) {
	RJson *j = r_json_parse (json);
	if (!j) {
		*error = strdup ("Failed to parse Anthropic response JSON");
		return NULL;
	}
	R2AI_ChatResponse *res = R_NEW0 (R2AI_ChatResponse);
	const RJson *u = r_json_get (j, "usage");
	if (u) {
		R2AI_Usage *usage = R_NEW0 (R2AI_Usage);
		usage->prompt_tokens = r_json_get_num (u, "input_tokens");
		usage->completion_tokens = r_json_get_num (u, "output_tokens");
		usage->total_tokens = usage->prompt_tokens + usage->completion_tokens;
		res->usage = usage;
	}
	R2AI_Message *msg = R_NEW0 (R2AI_Message);
	msg->role = strdup ("assistant");
	RStrBuf *sb = r_strbuf_new ("");
	const RJson *content = r_json_get (j, "content");
	if (content && content->type == R_JSON_ARRAY) {
		msg->content_blocks = r2ai_content_blocks_new ();
		const RJson *item;
		for (item = content->children.first; item; item = item->next) {
			char *type = jstr (item, "type");
			if (!type) {
				continue;
			}
			R2AI_ContentBlock *b = R_NEW0 (R2AI_ContentBlock);
			b->type = type;
			parse_block (b, item, msg, sb);
			r_list_append (msg->content_blocks, b);
		}
	}
	msg->content = r_strbuf_drain (sb);
	res->message = msg;
	r_json_free (j);
	return res;
}
