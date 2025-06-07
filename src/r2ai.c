/* r2ai - Copyright 2023-2025 pancake */

#define R_LOG_ORIGIN "r2ai"

#include "r2ai.h"

// External declaration for cmd_r2ai_a - implemented in auto.c
R_IPI void cmd_r2ai_a(RCore *core, const char *user_query);

static R_TH_LOCAL RVdb *db = NULL;

#define VDBDIM 16

static void refresh_embeddings(RCore *core) {
	RListIter *iter, *iter2;
	char *line;
	char *file;
	// refresh embeddings database
	r_vdb_free (db);
	db = r_vdb_new (VDBDIM);
	// enumerate .txt files in directory
	const char *path = r_config_get (core->config, "r2ai.data.path");
	RList *files = r_sys_dir (path);
	if (r_list_empty (files)) {
		R_LOG_WARN ("Cannot find any file in r2ai.data.path");
	}
	r_list_foreach (files, iter, file) {
		if (!r_str_endswith (file, ".txt")) {
			continue;
		}
		R_LOG_DEBUG ("Index %s", file);
		char *filepath = r_file_new (path, file, NULL);
		char *text = r_file_slurp (filepath, NULL);
		if (text) {
			RList *lines = r_str_split_list (text, "\n", -1);
			r_list_foreach (lines, iter2, line) {
				if (r_str_trim_head_ro (line)[0] == 0) {
					continue;
				}
				r_vdb_insert (db, line);
				R_LOG_DEBUG ("Insert %s", line);
			}
			r_list_free (lines);
		}
		free (filepath);
	}
	r_list_free (files);
}

static RCoreHelpMessage help_msg_r2ai = {
	"Usage:",
	"r2ai",
	" [-args] [...]",
	"r2ai",
	" -d",
	"Decompile current function",
	"r2ai",
	" -dr",
	"Decompile current function (+ 1 level of recursivity)",
	"r2ai",
	" -a [query]",
	"Resolve question using auto mode",
	"r2ai",
	" -e",
	"Same as '-e r2ai.'",
	"r2ai",
	" -h",
	"Show this help message",
	"r2ai",
	" -i [file] [query]",
	"read file and ask the llm with the given query",
	"r2ai",
	" -m",
	"show selected model, list suggested ones, choose one",
	"r2ai",
	" -n",
	"suggest a better name for the current function",
	"r2ai",
	" -r",
	"enter the chat repl",
	"r2ai",
	" -L",
	"show chat logs (See -Lj for json)",
	"r2ai",
	" -L-[N]",
	"delete the last (or N last messages from the chat history)",
	"r2ai",
	" -R",
	"reset the chat conversation context",
	"r2ai",
	" -Rq ([text])",
	"refresh and query embeddings (see r2ai.data)",
	"r2ai",
	" -s",
	"function signature",
	"r2ai",
	" -x",
	"explain current function",
	"r2ai",
	" -v",
	"suggest better variables names and types",
	"r2ai",
	" -V[r]",
	"find vulnerabilities in the decompiled code (-Vr uses -dr)",
	"r2ai",
	" [arg]",
	"send a post request to talk to r2ai and print the output",
	NULL
};

#if 0
// TODO: use it for r2ai.data.reason
static char *vdb_from(RCore *core, const char *prompt) {
	char *q = r_str_newf (
		"# Instruction\n"
		"Deconstruct the prompt and respond ONLY with the list of multiple prompts necessary to resolve it\n"
		"## Prompt\n%s\n",
		prompt);
	char *error = NULL;
	R2AIArgs vdb_args = {
		.input = q,
		.error = &error,
		.dorag = false
	};
	char *r = r2ai (core, vdb_args);
	if (error) {
		free (q);
		free (r);
		return NULL;
	}
	return r;
}

static char *rag(RCore *core, const char *content, const char *prompt) {
	char *q = r_str_newf (
		"# Instruction\n"
		"Filter the statements. Respond ONLY the subset of statements matching the prompt. Do not introduce the output. Do not use markdown\n"
		"## Prompt\n%s\n"
		"## Statements\n%s\n",
		prompt, content);
	char *error = NULL;
	R2AIArgs rag_args = {
		.input = q,
		.error = &error,
		.dorag = false
	};
	char *r = r2ai (core, rag_args);
	if (error) {
		free (q);
		free (r);
		return NULL;
	}
	return r;
}
#endif

R_IPI R2AI_ChatResponse *r2ai_llmcall(RCore *core, R2AIArgs args) {
	R2AI_ChatResponse *res = NULL;
	const char *provider = r_config_get (core->config, "r2ai.api");
	if (!provider) {
		provider = "gemini";
	}
	if (!args.model) {
		args.model = strdup (r_config_get (core->config, "r2ai.model"));
	}
	args.provider = strdup (provider);

	if (!args.max_tokens) {
		args.max_tokens = r_config_get_i (core->config, "r2ai.max_tokens");
	}
	if (!args.temperature) {
		args.temperature = atof (r_config_get (core->config, "r2ai.temperature"));
	}

	const char *api_key_env = r_str_newf ("%s_API_KEY", provider);
	char *api_key_env_copy = strdup (api_key_env);

	r_str_case (api_key_env_copy, true);
	const char *api_key_filename = r_str_newf ("~/.r2ai.%s-key", provider);
	char *api_key = NULL;

	char *s = r_sys_getenv (api_key_env_copy);
	if (R_STR_ISNOTEMPTY (s)) {
		api_key = s;
	} else {
		free (s);
		char *absolute_apikey = r_file_abspath (api_key_filename);
		if (r_file_exists (absolute_apikey)) {
			api_key = r_file_slurp (absolute_apikey, NULL);
		}
		free (absolute_apikey);
	}
	free (api_key_env_copy);

	if (api_key) {
		r_str_trim (api_key);
		args.api_key = api_key;
	}
	// Make sure we have an API key before proceeding
	if (strcmp (provider, "ollama")) {
		if (R_STR_ISEMPTY (args.api_key)) {
			R_LOG_ERROR ("No API key found for %s provider. Please set one with: r2ai "
				    "-e %s.api_key=YOUR_KEY",
				provider, provider);
			return NULL;
		}
	}

	// Set system_prompt from config if it's not already set
	if (!args.system_prompt) {
		args.system_prompt = r_config_get (core->config, "r2ai.system");
	}
	if (!args.messages) {
		args.messages = r2ai_msgs_new ();
	}
	int context_pullback = -1;
	// context and user message
	if (args.input && r_config_get_b (core->config, "r2ai.data")) {
		const int K = r_config_get_i (core->config, "r2ai.data.nth");
		if (!db) {
			db = r_vdb_new (VDBDIM);
			refresh_embeddings (core);
		}
		RStrBuf *sb = r_strbuf_new ("");
		r_strbuf_appendf (sb, "\n## Query\n\n%s\n## Context\n", args.input);
		RVdbResultSet *rs = r_vdb_query (db, args.input, K);
		if (rs) {
			int i;
			for (i = 0; i < rs->size; i++) {
				RVdbResult *r = &rs->results[i];
				KDNode *n = r->node;
				r_strbuf_appendf (sb, "- %s.\n", n->text);
			}
			r_vdb_result_free (rs);
		}
		char *m = r_strbuf_drain (sb);
		R2AI_Message msg = { .role = "user", .content = m };
		context_pullback = args.messages->n_messages;
		r2ai_msgs_add (args.messages, &msg);
		free (m);
		// TODO: we can save the msg without context
	}

	// Add the rest of the messages one by one
	if (!args.messages && args.input) {
		R2AI_Message msg = { .role = "user", .content = args.input };
		args.messages = r2ai_msgs_new ();
		r2ai_msgs_add (args.messages, &msg);
	}

	args.thinking_tokens = r_config_get_i (core->config, "r2ai.thinking_tokens");

	R_LOG_DEBUG ("Using provider: %s", provider);
	if (strcmp (provider, "anthropic") == 0) {
		res = r2ai_anthropic (core, args);
	} else {
		res = r2ai_openai (core, args);
	}
	if (context_pullback != -1) {
		R2AI_Message *msg = &args.messages->messages[context_pullback];
		free ((char *)msg->content);
		msg->content = strdup (args.input);
	}
	if (*args.error) {
		R_LOG_ERROR ("%s", *args.error);
		free (*args.error);
		*args.error = NULL;
	}

	return res;
}

R_IPI char *r2ai(RCore *core, R2AIArgs args) {
	if (R_STR_ISEMPTY (args.input) && !args.messages) {
		if (args.error) {
			*args.error = r_str_newf ("Usage: r2ai [-h] [prompt]");
		}
		return NULL;
	}

	if (R_STR_ISEMPTY (args.system_prompt)) {
		args.system_prompt = r_config_get (core->config, "r2ai.system");
	}

	R2AI_Messages *msgs = r2ai_msgs_new ();

	if (args.input) {
		R2AI_Message msg = { .role = "user", .content = args.input };
		r2ai_msgs_add (msgs, &msg);
	}

	args.messages = msgs;

	// Call the r2ai_llmcall function to get the message
	R2AI_ChatResponse *res = r2ai_llmcall (core, args);
	if (!res) {
		return NULL;
	}

	// Extract content from the response
	char *content = NULL;

	// If content is present in the result message, use it
	if (res->message) {
		if (res->message->content) {
			content = strdup (res->message->content);
		}
	}

	// Free the message properly using r2ai_message_free
	if (res->message) {
		r2ai_message_free ((R2AI_Message *)res->message);
	}

	// Free the response struct itself
	free (res);

	return content;
}

static void cmd_r2ai_d(RCore *core, const char *input, const bool recursive) {
	const char *prompt = r_config_get (core->config, "r2ai.prompt");
	const char *lang = r_config_get (core->config, "r2ai.lang");
	char *full_prompt;
	if (!R_STR_ISEMPTY (lang)) {
		full_prompt = r_str_newf (
			"%s. Translate the code into %s programming language.", prompt, lang);
	} else {
		full_prompt = strdup (prompt);
	}
	char *cmds = strdup (r_config_get (core->config, "r2ai.cmds"));
	RStrBuf *sb = r_strbuf_new (full_prompt);
	RList *cmdslist = r_str_split_list (cmds, ",", -1);
	RListIter *iter;
	const char *cmd;
	RList *refslist = NULL;
	if (recursive) {
		char *refs = r_core_cmd_str (core, "axff~^C[2]~$$");
		refslist = r_str_split_list (refs, ",", 0);
		free (refs);
	}
	r_list_foreach (cmdslist, iter, cmd) {
		char *dec = r_core_cmd_str (core, cmd);
		r_strbuf_append (sb, "\n[BEGIN]\n");
		r_strbuf_append (sb, dec);
		r_strbuf_append (sb, "[END]\n");
		free (dec);
		if (recursive) {
			RListIter *iter2;
			char *at;
			r_list_foreach (refslist, iter2, at) {
				ut64 n = r_num_get (core->num, at);
				if (core->num->nc.errors) {
					continue;
				}
				char *dec = r_core_cmd_str_at (core, n, cmd);
				r_strbuf_append (sb, "\n[BEGIN]\n");
				r_strbuf_append (sb, dec);
				r_strbuf_append (sb, "[END]\n");
				free (dec);
			}
		}
	}
	r_list_free (refslist);
	char *s = r_strbuf_drain (sb);
	char *error = NULL;
	R2AIArgs d_args = { .input = s, .error = &error, .dorag = true };
	char *res = r2ai (core, d_args);
	free (s);
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		r_cons_printf ("%s\n", res);
	}
	free (res);
	r_list_free (cmdslist);
}

static void cmd_r2ai_x(RCore *core) {
	const char *hlang = r_config_get (core->config, "r2ai.hlang");
	char *explain_prompt = r_str_newf (
		"Analyze function calls, comments and strings, ignore registers and "
		"memory accesess. Considering the references and involved loops make "
		"explain the purpose of this function in one or two short sentences. "
		"Output must be only the translation of the explanation in %s",
		hlang);
	char *s = r_core_cmd_str (core, "r2ai -d");

	// Create conversation
	R2AI_Messages *msgs = create_conversation (s);
	if (!msgs) {
		R_LOG_ERROR ("Failed to create conversation");
		free (s);
		free (explain_prompt);
		return;
	}

	// Process the conversation with custom system prompt (will print the result)
	process_messages (core, msgs, explain_prompt, 1);

	// Free temporary messages
	r2ai_msgs_free (msgs);

	free (s);
	free (explain_prompt);
}

static void cmd_r2ai_repl(RCore *core) {
	RStrBuf *sb = r_strbuf_new ("");
	while (true) {
#if R2_VERSION_NUMBER >= 50909
		r_line_set_prompt (core->cons->line, ">>> ");
		const char *ptr = r_line_readline (core->cons);
#else
		r_line_set_prompt (">>> ");
		const char *ptr = r_line_readline ();
#endif
		if (R_STR_ISEMPTY (ptr)) {
			break;
		}
		if (*ptr == '/') {
			if (ptr[1] == '?' || r_str_startswith (ptr, "/help")) {
				r_cons_println ("/help    show this help");
				r_cons_println ("/reset   reset conversation");
				r_cons_println ("/quit    same as ^D, leave the repl");
			} else if (r_str_startswith (ptr, "/reset")) {
				r_strbuf_free (sb);
				sb = r_strbuf_new ("");
				continue;
			} else if (r_str_startswith (ptr, "/quit")) {
				break;
			}
		}
		r_strbuf_appendf (sb, "User: %s\n", ptr);
		const char *a = r_strbuf_tostring (sb);
		char *error = NULL;
		char *res =
			r2ai (core, (R2AIArgs){ .input = a, .error = &error, .dorag = true });
		if (error) {
			R_LOG_ERROR ("%s", error);
			free (error);
		} else if (res) {
			r_strbuf_appendf (sb, "Assistant: %s\n", res);
			r_cons_println (res);
			r_cons_flush ();
		}
		free (res);
	}
	r_strbuf_free (sb);
}

static void cmd_r2ai_R(RCore *core, const char *q) {
	if (!r_config_get_b (core->config, "r2ai.data")) {
		R_LOG_ERROR ("r2ai -e r2ai.data=true");
		return;
	}
	if (R_STR_ISEMPTY (q)) {
		if (db) {
			r_vdb_free (db);
			db = NULL;
		}
		refresh_embeddings (core);
	} else {
		refresh_embeddings (core);
		const int K = r_config_get_i (core->config, "r2ai.data.nth");
		RVdbResultSet *rs = r_vdb_query (db, q, K);

		if (rs) {
			R_LOG_DEBUG ("Query: \"%s\"", q);
			R_LOG_DEBUG ("Found up to %d neighbors (actual found: %d)", K, rs->size);
			int i;
			for (i = 0; i < rs->size; i++) {
				RVdbResult *r = &rs->results[i];
				KDNode *n = r->node;
				float dist_sq = r->dist_sq;
				float cos_sim = 1.0f - (dist_sq * 0.5f); // for normalized vectors
				printf ("%2d) dist_sq=%.4f cos_sim=%.4f text=\"%s\"\n", i + 1, dist_sq,
					cos_sim, (n->text ? n->text : "(null)"));
			}
			r_vdb_result_free (rs);
		} else {
			R_LOG_ERROR ("No vdb results found");
		}
	}
}

static void cmd_r2ai_n(RCore *core) {
	char *s = r_core_cmd_str (core, "r2ai -d");
	char *q =
		r_str_newf ("output only the radare2 commands in plain text without "
			   "markdown. Give me a better name for this function. the "
			   "output must be: 'afn NEWNAME'. do not include the function "
			   "code, only the afn line. consider: \n```c\n%s\n```",
			s);
	char *error = NULL;
	char *res =
		r2ai (core, (R2AIArgs){ .input = q, .error = &error, .dorag = true });
	free (s);
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		r_cons_printf ("%s\n", res);
	}
	free (res);
	free (q);
}

static void cmd_r2ai_i(RCore *core, const char *arg) {
	char *fname = strdup (arg);
	char *query = strchr (fname, ' ');
	if (query) {
		*query++ = 0;
	}
	char *s = r_file_slurp (fname, NULL);
	if (R_STR_ISEMPTY (s)) {
		R_LOG_ERROR ("Cannot open %s", fname);
		free (fname);
		return;
	}
	char *q = r_str_newf ("%s\n```\n%s\n```\n", query, s);
	char *error = NULL;
	char *res =
		r2ai (core, (R2AIArgs){ .input = q, .error = &error, .dorag = true });
	free (s);
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		r_cons_printf ("%s\n", res);
	}
	free (fname);
	free (res);
	free (q);
}

static void cmd_r2ai_s(RCore *core) {
	char *afv = r_core_cmd_str (core, "afv");
	r_str_trim (afv);
	char *s = r_core_cmd_str (core, "r2ai -d");
	r_str_trim (s);
	if (R_STR_ISEMPTY (s)) {
		R_LOG_ERROR ("Cannot find function");
		free (afv);
		return;
	}
	char *q = r_str_newf (
		"analyze the uses of the arguments and return value to infer the "
		"signature, identify which is the correct type for the resturn. Do NOT "
		"print the function body, ONLY output the function signature, ignore '@' "
		"in argument types because it must be used in a C header:\n```\n%s\n``` "
		"source code:\n```\n%s\n```\n",
		afv, s);
	char *error = NULL;
	char *res =
		r2ai (core, (R2AIArgs){ .input = q, .error = &error, .dorag = true });
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		char *begin = strstr (res, "```");
		if (begin) {
			char *nl = strchr (begin, '\n');
			if (nl) {
				nl++;
				char *end = strstr (nl, "```");
				if (end) {
					*end = 0;
				}
				r_str_trim (nl);
				r_cons_printf ("'afs %s\n", nl);
			}
		}
	}
	free (afv);
	free (res);
	free (q);
	free (s);
}

static void cmd_r2ai_v(RCore *core) {
	char *s = r_core_cmd_str (core, "r2ai -d");
	char *afv = r_core_cmd_str (core, "afv");
	char *q = r_str_newf (
		"Output only the radare2 command without markdown, guess a better name "
		"and type for each local variable and function argument taking using. "
		"output an r2 script using afvn and afvt commands:\n```\n%s```",
		afv);
	char *error = NULL;
	char *res =
		r2ai (core, (R2AIArgs){ .input = q, .error = &error, .dorag = true });
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		r_cons_println (res);
	}
	free (afv);
	free (res);
	free (q);
	free (s);
}

static void cmd_r2ai_V(RCore *core, bool recursive) {
	char *s = r_core_cmd_str (core, recursive ? "r2ai -d" : "r2ai -dr");
	char *q = r_str_newf (
		"find vulnerabilities, dont show the code, only show the response, "
		"provide a sample exploit and suggest good practices:\n```\n%s```",
		s);
	char *error = NULL;
	char *res =
		r2ai (core, (R2AIArgs){ .input = q, .error = &error, .dorag = true });
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		r_cons_printf ("%s\n", res);
	}
	free (res);
	free (q);
	free (s);
}

static void cmd_r2ai_m(RCore *core, const char *input) {
	if (R_STR_ISEMPTY (input)) {
		r_cons_printf ("%s\n", r_config_get (core->config, "r2ai.model"));
		return;
	}
	r_config_lock (core->config, false);
	r_config_set (core->config, "r2ai.model", input);
	r_config_lock (core->config, true);
	r_cons_printf ("Model set to %s\n", input);
}

static void load_embeddings(RCore *core, RVdb *db) {
	RListIter *iter, *iter2;
	char *line;
	char *file;
	// enumerate .txt files in directory
	const char *path = r_config_get (core->config, "r2ai.data.path");
	RList *files = r_sys_dir (path);
	if (r_list_empty (files)) {
		R_LOG_WARN ("Cannot find any file in r2ai.data.path");
	}
	r_list_foreach (files, iter, file) {
		if (!r_str_endswith (file, ".txt")) {
			continue;
		}
		R_LOG_DEBUG ("Index %s", file);
		char *filepath = r_file_new (path, file, NULL);
		char *text = r_file_slurp (filepath, NULL);
		if (text) {
			RList *lines = r_str_split_list (text, "\n", -1);
			r_list_foreach (lines, iter2, line) {
				if (r_str_trim_head_ro (line)[0] == 0) {
					continue;
				}
				r_vdb_insert (db, line);
				R_LOG_DEBUG ("Insert %s", line);
			}
			r_list_free (lines);
		}
		free (filepath);
	}
	r_list_free (files);
}

static void cmd_r2ai(RCore *core, const char *input) {
	if (*input == '?' || r_str_startswith (input, "-h")) {
		r_core_cmd_help (core, help_msg_r2ai);
	} else if (r_str_startswith (input, "-e")) {
		const char *arg = r_str_trim_head_ro (input + 2);
		if (r_str_startswith (arg, "r2ai")) {
			r_core_cmdf (core, "-e %s", arg);
		} else {
			r_core_cmdf (core, "-e r2ai.%s", arg);
		}
	} else if (r_str_startswith (input, "-a")) {
		cmd_r2ai_a (core, r_str_trim_head_ro (input + 2));
	} else if (r_str_startswith (input, "-L-")) {
		const char *arg = r_str_trim_head_ro (input + 3);
		const int N = atoi (arg);
		R2AI_Messages *messages = r2ai_conversation_get ();
		if (!messages || messages->n_messages == 0) {
			r_cons_printf ("No conversation history available\n");
		} else {
			r2ai_delete_last_messages (messages, N);
			r_cons_printf ("Deleted %d message%s from chat history\n", N > 0 ? N : 1,
				(N > 0 && N != 1) ? "s" : "");
		}
	} else if (r_str_startswith (input, "-L")) {
		cmd_r2ai_logs (core);
	} else if (r_str_startswith (input, "-d")) {
		cmd_r2ai_d (core, r_str_trim_head_ro (input + 2), false);
	} else if (r_str_startswith (input, "-dr")) {
		cmd_r2ai_d (core, r_str_trim_head_ro (input + 2), true);
	} else if (r_str_startswith (input, "-x")) {
		cmd_r2ai_x (core);
	} else if (r_str_startswith (input, "-s")) {
		cmd_r2ai_s (core);
	} else if (r_str_startswith (input, "-S")) {
		if (db == NULL) {
			db = r_vdb_new (VDBDIM);
			load_embeddings (core, db);
		}
		const char *arg = r_str_trim_head_ro (input + 2);
		const int K = 10;
		RVdbResultSet *rs = r_vdb_query (db, arg, K);
		if (rs) {
			int i;
			eprintf ("Found up to %d neighbors (actual found: %d).\n", K, rs->size);
			for (i = 0; i < rs->size; i++) {
				RVdbResult *r = &rs->results[i];
				KDNode *n = r->node;
				r_cons_printf ("- (%.4f) %s\n", r->dist_sq, n->text);
			}
			r_vdb_result_free (rs);
		}
	} else if (r_str_startswith (input, "-i")) {
		cmd_r2ai_i (core, r_str_trim_head_ro (input + 2));
	} else if (r_str_startswith (input, "-v")) {
		cmd_r2ai_v (core);
	} else if (r_str_startswith (input, "-V")) {
		cmd_r2ai_V (core, false);
	} else if (r_str_startswith (input, "-Vr")) {
		cmd_r2ai_V (core, true);
	} else if (r_str_startswith (input, "-n")) {
		cmd_r2ai_n (core);
	} else if (r_str_startswith (input, "-r")) {
		cmd_r2ai_repl (core);
	} else if (r_str_startswith (input, "-R")) {
#if 0
		if (strlen (input) <= 2 || isspace (input[2])) {
			R2AI_Messages *messages = r2ai_conversation_get ();
			if (!messages || messages->n_messages == 0) {
				r_cons_printf ("No conversation history to reset\n");
			} else {
				r2ai_msgs_clear (messages);
				r_cons_printf ("Chat conversation context has been reset\n");
			}
		} else {
			cmd_r2ai_R (core, r_str_trim_head_ro (input + 2));
		}
#else
		cmd_r2ai_R (core, r_str_trim_head_ro (input + 2));
#endif
	} else if (r_str_startswith (input, "-Rq")) {
		cmd_r2ai_R (core, r_str_trim_head_ro (input + 3));
	} else if (r_str_startswith (input, "-m")) {
		cmd_r2ai_m (core, r_str_trim_head_ro (input + 2));
	} else if (r_str_startswith (input, "-")) {
		r_core_cmd_help (core, help_msg_r2ai);
	} else {
		char *err = NULL;
		char *res =
			r2ai (core, (R2AIArgs){ .input = input, .error = &err, .dorag = true });
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

R_IPI const char *r2ai_get_base_url(RCore *core, const char *provider) {
	const char *base_url = r_config_get (core->config, "r2ai.base_url");

	if (R_STR_ISNOTEMPTY (base_url)) {
		return base_url;
	}

	if (strcmp (provider, "openai") == 0) {
		return "https://api.openai.com/v1";
	} else if (strcmp (provider, "gemini") == 0) {
		return "https://generativelanguage.googleapis.com/v1beta/openai";
	} else if (strcmp (provider, "ollama") == 0) {
		return "http://localhost:11434/v1";
	} else if (strcmp (provider, "xai") == 0) {
		return "https://api.x.ai/v1";
	} else if (strcmp (provider, "anthropic") == 0) {
		return "https://api.anthropic.com/v1";
	} else if (strcmp (provider, "openapi") == 0) {
		return "http://127.0.0.1:11434";
	} else if (strcmp (provider, "openrouter") == 0) {
		return "https://openrouter.ai/api/v1";
	} else if (strcmp (provider, "groq") == 0) {
		return "https://api.groq.com/openai/v1";
	} else if (strcmp (provider, "mistral") == 0) {
		return "https://api.mistral.ai/v1";
	}

	return NULL;
}

static RList *fetch_available_models(RCore *core, const char *provider) {
	const char *base_url = r2ai_get_base_url (core, provider);

	if (!base_url) {
		return NULL;
	}

	// Create models endpoint URL
	char *models_url = r_str_newf ("%s/models", base_url);
	if (!models_url) {
		return NULL;
	}

	// Get API key for authentication (except for ollama and openapi)
	char *api_key = NULL;
	if (strcmp (provider, "ollama") != 0 && strcmp (provider, "openapi") != 0) {
		const char *api_key_env = r_str_newf ("%s_API_KEY", provider);
		char *api_key_env_copy = strdup (api_key_env);
		r_str_case (api_key_env_copy, true);

		char *s = r_sys_getenv (api_key_env_copy);
		if (R_STR_ISNOTEMPTY (s)) {
			api_key = s;
		} else {
			free (s);
			const char *api_key_filename = r_str_newf ("~/.r2ai.%s-key", provider);
			char *absolute_apikey = r_file_abspath (api_key_filename);
			if (r_file_exists (absolute_apikey)) {
				api_key = r_file_slurp (absolute_apikey, NULL);
				if (api_key) {
					r_str_trim (api_key);
				}
			}
			free (absolute_apikey);
		}
		free (api_key_env_copy);
	}

	// Setup headers based on provider
	const char *headers[4] = { "Content-Type: application/json", NULL, NULL, NULL };
	char *auth_header = NULL;
	char *version_header = NULL;

	if (api_key) {
		if (strcmp (provider, "anthropic") == 0) {
			// Anthropic uses different header format
			auth_header = r_str_newf ("x-api-key: %s", api_key);
			version_header = strdup ("anthropic-version: 2023-06-01");
			headers[1] = auth_header;
			headers[2] = version_header;
		} else {
			// Standard OpenAI-compatible format
			auth_header = r_str_newf ("Authorization: Bearer %s", api_key);
			headers[1] = auth_header;
		}
	}

	// Make HTTP GET request
	int code = 0;
	char *response = r2ai_http_get (models_url, headers, &code, NULL);

	free (models_url);
	free (auth_header);
	free (version_header);
	free (api_key);

	if (!response || code != 200) {
		R_LOG_DEBUG ("Failed to fetch models from %s (code: %d)", provider, code);
		free (response);
		return NULL;
	}

	// Parse JSON response
	RList *models = r_list_newf (free);
	if (!models) {
		free (response);
		return NULL;
	}

	RJson *json = r_json_parse (response);
	if (json) {
		const RJson *data = r_json_get (json, "data");
		if (data && data->type == R_JSON_ARRAY) {
			const RJson *model_item = data->children.first;
			while (model_item) {
				const RJson *id = r_json_get (model_item, "id");
				if (id && id->type == R_JSON_STRING && R_STR_ISNOTEMPTY (id->str_value)) {
					r_list_append (models, strdup (id->str_value));
				}
				model_item = model_item->next;
			}
		}
		r_json_free (json);
	}

	free (response);
	return models;
}

static bool cb_r2ai_api(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		r_cons_println ("ollama");
		r_cons_println ("openai");
		r_cons_println ("openapi");
		r_cons_println ("anthropic");
		r_cons_println ("gemini");
		r_cons_println ("openrouter");
		r_cons_println ("mistral");
		r_cons_println ("groq");
		r_cons_println ("xai");
		return false;
	}
	return true;
}

static bool cb_r2ai_model(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	RCore *core = (RCore *)user;
	const char *api = r_config_get (core->config, "r2ai.api");
	if (*node->value == '?') {
		// Try to fetch models dynamically first
		RList *models = fetch_available_models (core, api);
		if (models && !r_list_empty (models)) {
			RListIter *iter;
			char *model;
			r_list_foreach (models, iter, model) {
				r_cons_println (model);
			}
			r_list_free (models);
		} else {
			// Fallback to static lists if dynamic fetching fails
			if (!strcmp (api, "gemini")) {
				r_cons_println ("gemini-1.5-flash");
				r_cons_println ("gemini-1.0-pro");
			} else if (!strcmp (api, "ollama")) {
				char *s = r_sys_cmd_str ("ollama ls", NULL, NULL);
				if (s) {
					RList *items = r_str_split_list (s, "\n", 0);
					RListIter *iter;
					char *item;
					r_list_foreach (items, iter, item) {
						if (R_STR_ISEMPTY (item) || r_str_startswith (item, "NAME")) {
							continue;
						}
						char *s = strchr (item, ' ');
						if (s) {
							*s = 0;
						}
						r_cons_println (item);
					}
					r_list_free (items);
					free (s);
				}
			}
		}
		return false;
	}
	return true;
}

static int r2ai_init(void *user, const char *input) {
	RCmd *cmd = (RCmd *)user;
	RCore *core = cmd->data;

	// Initialize conversation container
	r2ai_conversation_init ();

	r_config_lock (core->config, false);
	r_config_set_cb (core->config, "r2ai.api", "openai", &cb_r2ai_api);
	r_config_set_cb (core->config, "r2ai.model", "gpt-4o-mini", &cb_r2ai_model);
	r_config_set (core->config, "r2ai.base_url", "");
	r_config_set_i (core->config, "r2ai.max_tokens", 5128);
	r_config_set_i (core->config, "r2ai.thinking_tokens", 0);
	r_config_set (core->config, "r2ai.temperature", "0.01");
	r_config_set (core->config, "r2ai.cmds", "pdc");
	r_config_set (core->config, "r2ai.lang", "C");
	r_config_set_b (core->config, "r2ai.data", false);
	r_config_set_b (core->config, "r2ai.data.reason", false);
	r_config_set (core->config, "r2ai.data.path", "/tmp/embeds");
	r_config_set_i (core->config, "r2ai.data.nth", 10);
	r_config_set (core->config, "r2ai.hlang", "english");
	r_config_set (
		core->config, "r2ai.system",
		"You are a reverse engineer. The user is reversing a binary, using "
		"radare2. The user will ask questions about the binary and you will "
		"respond with the answer to the best of your ability.");
	r_config_set (
		core->config, "r2ai.prompt",
		"Rewrite this function and respond ONLY with code, replace goto/labels "
		"with if/else/for, use NO explanations, NO markdown, Simplify as much as "
		"possible, use better variable names, take function arguments and "
		"strings from comments like 'string:'");
	r_config_set_b (core->config, "r2ai.stream", false);
	r_config_set_i (core->config, "r2ai.auto.max_runs", 50);
	r_config_set_b (core->config, "r2ai.auto.hide_tool_output", false);
	r_config_set (core->config, "r2ai.auto.init_commands", "aaa;iI;afl");
	r_config_set_b (core->config, "r2ai.auto.ask_to_execute", true);
	r_config_set_b (core->config, "r2ai.auto.reset_on_query", false);
	r_config_set_b (core->config, "r2ai.chat.show_cost", true);
	// Configure HTTP timeout in seconds
	r_config_set_i (core->config, "r2ai.http.timeout", 120);
	// Configure HTTP rate limiting and retry parameters
	r_config_set_i (core->config, "r2ai.http.max_retries", 10);
	r_config_set_i (core->config, "r2ai.http.max_backoff", 30);
	r_config_lock (core->config, true);
	return true;
}

static int r2ai_fini(void *user, const char *input) {
	RCmd *cmd = (RCmd *)user;
	RCore *core = cmd->data;
	r_config_lock (core->config, false);
	r_config_rm (core->config, "r2ai.api");
	r_config_rm (core->config, "r2ai.cmds");
	r_config_rm (core->config, "r2ai.model");
	r_config_rm (core->config, "r2ai.prompt");
	r_config_rm (core->config, "r2ai.stream");
	r_config_rm (core->config, "r2ai.system");
	r_config_rm (core->config, "r2ai.data");
	r_config_rm (core->config, "r2ai.data.path");
	r_config_rm (core->config, "r2ai.data.nth");
	r_config_rm (core->config, "r2ai.auto.reset_on_query");
	r_config_rm (core->config, "r2ai.http.timeout");
	r_config_rm (core->config, "r2ai.http.max_retries");
	r_config_rm (core->config, "r2ai.http.max_backoff");
	r_config_lock (core->config, true);

	// Free the conversation
	r2ai_conversation_free ();

	// Free the OpenAI resources
	r2ai_openai_fini ();

	// Free the vector database if we have one
	if (db) {
		r_vdb_free (db);
		db = NULL;
	}
	return true;
}

static int r_cmd_r2ai_client(void *user, const char *input) {
	RCore *core = (RCore *)user;
	if (r_str_startswith (input, "r2ai")) {
		cmd_r2ai (core, r_str_trim_head_ro (input + 4));
		return true;
	}
	return false;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_r2ai_client = {
	.meta = {
		.name = "r2ai",
		.desc = "r2ai plugin in plain C",
		.author = "pancake",
		.version = "0.9.6",
		.license = "MIT",
	},
	.init = r2ai_init,
	.fini = r2ai_fini,
	.call = r_cmd_r2ai_client,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = { .type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_r2ai_client,
	.version = R2_VERSION };
#endif
