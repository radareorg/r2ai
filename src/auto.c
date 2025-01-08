#include "r2ai.h"

static const char Gprompt_auto[] = \
"# Function Calling\n" \
"\n" \
"Respond ONLY using JSON. You are a smart assistant designed to process user queries and decide if a local function needs to be executed. Follow these steps:\n" \
"1. Analyze the user input to determine if it requires invoking a local function or just returning a direct response.\n" \
"2. If it requires a function call:\n" \
"    - Use the key \"action\": \"execute_function\".\n" \
"    - Provide the \"function_name\" as a string.\n" \
"    - Include \"parameters\" as a dictionary of key-value pairs matching the required function arguments.\n" \
"    - Optionally, provide a \"response\" to summarize your intent.\n" \
"3. If no function is required:\n" \
"    - Use the key \"action\": \"reply\".\n" \
"    - Include \"response\" with the direct answer to the user query.\n" \
"\n" \
"Return the result as a JSON object.\n" \
"\n" \
"## Here is an example:\n" \
"\n" \
"User Query: \"Count how many functions.\"\n" \
"Response:\n" \
"{\n" \
"    \"action\": \"execute_function\",\n" \
"    \"function_name\": \"r2cmd\",\n" \
"    \"parameters\": {\n" \
"        \"r2cmd\": \"aflc\",\n" \
"    }\n" \
"    \"response\": \"Count how many functions do we have\"\n" \
"}\n" \
"\n" \
"# Now, analyze the following user input:\n";

R_IPI void cmd_r2ai_a(RCore *core, const char *user_query) {
	RList *replies = r_list_newf (free);
	while (true) {
		RStrBuf *sb = r_strbuf_new ("");
		r_strbuf_append (sb, Gprompt_auto);
		if (!r_list_empty (replies)) {
			r_strbuf_append (sb, "\n## Executed function results:\n");
			char *r;
			RListIter *iter;
			r_list_foreach (replies, iter, r) {
				r_strbuf_appendf (sb, "%s\n", r);
			}
		}
		r_strbuf_appendf (sb, "## User prompt\n%s\n", user_query);

		char *q = r_strbuf_drain (sb);
		char *error = NULL;
		char *res = r2ai (core, q, &error);
		free (q);
		{
			RJson *jres = r_json_parse (res);
			if (!jres) {
				R_LOG_ERROR ("Invalid json");
				r_cons_printf ("%s\n", res);
				free (res);
				break;
			}
			const RJson *action = r_json_get (jres, "action");
			if (action) {
				const char *action_str = action->str_value;
				if (!strcmp (action_str, "execute_function") || !strcmp (action_str, "r2cmd")) {
					const RJson *parameters = r_json_get (jres, "parameters");
					if (!parameters) {
						goto badjson;
					}
					const RJson *r2cmd = r_json_get (parameters, "r2cmd");
					if (!r2cmd) {
						goto badjson;
					}
					R_LOG_INFO ("[r2cmd] Running: %s", r2cmd);
					char *res2 = r_core_cmd_str (core, r2cmd->str_value);
					PJ *pj = pj_new ();
					pj_o (pj);
					pj_ks (pj, "action", "function_response");
					pj_ks (pj, "r2cmd", r2cmd->str_value);
					pj_ks (pj, "response", res2);
					pj_end (pj);
					char *reply = pj_drain (pj);
					r_list_append (replies, reply);
					free (res2);
				} else if (!strcmp (action_str, "reply")) {
					const RJson *res = r_json_get (jres, "response");
					if (!res) {
						goto badjson;
					}
					r_cons_printf ("%s\n", res->str_value);
				}
			} else {
				r_cons_printf ("%s\n", res);
			}
badjson:
			r_json_free (jres);
		}

		free (res);
	}
}

