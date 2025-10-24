/* r2ai - Copyright 2023-2025 pancake */

#define R_LOG_ORIGIN "r2ai"

#include "r2ai.h"
#include "r2ai_priv.h"

static RCoreHelpMessage help_msg_r2ai = {
	"Usage:",
	"r2ai", " [-args] [...]",
	"r2ai", " -d", "Decompile current function",
	"r2ai", " -d [query]", "Ask a question on the current function",
	"r2ai", " -dr", "Decompile current function (+ 1 level of recursivity)",
	"r2ai", " -a [query]", "Resolve question using auto mode",
	"r2ai", " -e (k(=v))", "Same as '-e r2ai.'",
	"r2ai", " -E", "Edit the r2ai rc file",
	"r2ai", " -h", "Show this help message",
	"r2ai", " -i [file] [query]", "read file and ask the llm with the given query",
	"r2ai", " -m", "show selected model, list suggested ones, choose one",
	"r2ai", " -p [provider]", "set LLM provider (openai, anthropic, gemini, etc.)",
	"r2ai", " -q", "list available query prompts",
	"r2ai", " -q [name] (inst)", "run predefined prompt with optional instructions",
	"r2ai", " -r", "enter the chat repl",
	"r2ai", " -L", "show chat logs (See -Lj for json). Only for auto mode.",
	"r2ai", " -L-[N]", "delete the last (or N last messages from the chat history)",
	"r2ai", " -R", "reset the chat conversation context",
	"r2ai", " -Rq ([text])", "refresh and query embeddings (see r2ai.data)",
	"r2ai", " [query]", "query the selected model+provider with the given query",
	NULL
};

R_API char *r2ai(RCorePluginSession *cps, R2AIArgs args) {
	RCore *core = cps->core;
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
		R2AI_Message msg = { .role = "user", .content = (char *)args.input };
		r2ai_msgs_add (msgs, &msg);
	}

	args.messages = msgs;

	R2AI_ChatResponse *res = r2ai_llmcall (cps, args);
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

static void cmd_r2ai_d(RCorePluginSession *cps, const char *input, const bool recursive) {
	RCore *core = cps->core;
	const char *prompt = r_config_get (core->config, "r2ai.prompt");
	const char *lang = r_config_get (core->config, "r2ai.lang");
	char *full_prompt;
	if (!R_STR_ISEMPTY (input)) {
		R_LOG_DEBUG ("User question: %s", input);
		full_prompt = strdup (input);
	} else {
		if (!R_STR_ISEMPTY (lang)) {
			full_prompt = r_str_newf ("%s. Translate the code into %s programming language.", prompt, lang);
		} else {
			full_prompt = strdup (prompt);
		}
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
	char *res = r2ai (cps, d_args);
	free (s);
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		R2_PRINTF ("%s\n", res);
	}
	free (res);
	r_list_free (cmdslist);
}

static void cmd_r2ai_repl(RCorePluginSession *cps) {
	RCore *core = cps->core;
	RStrBuf *sb = r_strbuf_new ("");
	while (true) {
		r_line_set_prompt (core->cons->line, ">>> ");
		const char *ptr = r_line_readline (core->cons);
		if (R_STR_ISEMPTY (ptr)) {
			break;
		}
		if (*ptr == '/') {
			if (ptr[1] == '?' || r_str_startswith (ptr, "/help")) {
				R2_PRINTLN ("/help    show this help");
				R2_PRINTLN ("/reset   reset conversation");
				R2_PRINTLN ("/quit    same as ^D, leave the repl");
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
			r2ai (cps, (R2AIArgs){ .input = a, .error = &error, .dorag = true });
		if (error) {
			R_LOG_ERROR ("%s", error);
			free (error);
		} else if (res) {
			r_strbuf_appendf (sb, "Assistant: %s\n", res);
			R2_PRINTF ("%s\n", res);
			R2_FLUSH ();
		}
		free (res);
	}
	r_strbuf_free (sb);
}

static void cmd_r2ai_R(RCorePluginSession *cps, const char *q) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	if (!r_config_get_b (core->config, "r2ai.data")) {
		R_LOG_ERROR ("r2ai -e r2ai.data=true");
		return;
	}
	if (R_STR_ISEMPTY (q)) {
		if (state->db) {
			r_vdb_free (state->db);
			state->db = NULL;
		}
		r2ai_refresh_embeddings (cps);
	} else {
		r2ai_refresh_embeddings (cps);
		const int K = r_config_get_i (core->config, "r2ai.data.nth");
		RVdbResultSet *rs = r_vdb_query (state->db, q, K);

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
					cos_sim, (n->text? n->text: "(null)"));
			}
			r_vdb_result_free (rs);
		} else {
			R_LOG_ERROR ("No vdb results found");
		}
	}
}

static void cmd_r2ai_i(RCorePluginSession *cps, const char *arg) {
	RCore *core = cps->core;
	char *fname = strdup (arg);
	char *query = strchr (fname, ' ');
	if (query) {
		*query++ = 0;
	}
	char *s = r_file_slurp (fname, NULL);
	if (R_STR_ISNOTEMPTY (s)) {
		R_LOG_ERROR ("Cannot open %s", fname);
		free (fname);
		return;
	}
	char *q = r_str_newf ("%s\n```\n%s\n```\n", query, s);
	char *error = NULL;
	char *res =
		r2ai (cps, (R2AIArgs){ .input = q, .error = &error, .dorag = true });
	free (s);
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		R2_PRINTF ("%s\n", res);
	}
	free (fname);
	free (res);
	free (q);
}

static void cmd_r2ai_m(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	if (R_STR_ISEMPTY (input)) {
		R2_PRINTF ("%s\n", r_config_get (core->config, "r2ai.model"));
	} else {
		r_config_set (core->config, "r2ai.model", input);
	}
}

static void load_embeddings(RCorePluginSession *cps) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
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
				r_vdb_insert (state->db, line);
				R_LOG_DEBUG ("Insert %s", line);
			}
			r_list_free (lines);
		}
		free (filepath);
	}
	r_list_free (files);
}

static void cmd_r2ai(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	if (*input == '?' || r_str_startswith (input, "-h")) {
		r_core_cmd_help (core, help_msg_r2ai);
	} else if (r_str_startswith (input, "-E")) {
		char *rc_path = r_file_home (".config/r2ai/rc");
		r_cons_editor (core->cons, rc_path, NULL);
		free (rc_path);
	} else if (r_str_startswith (input, "-e")) {
		const char *arg = r_str_trim_head_ro (input + 2);
		if (r_str_startswith (arg, "r2ai")) {
			r_core_cmdf (core, "-e %s", arg);
		} else {
			r_core_cmdf (core, "-e r2ai.%s", arg);
		}
	} else if (r_str_startswith (input, "-a")) {
		cmd_r2ai_a (cps, r_str_trim_head_ro (input + 2));
	} else if (r_str_startswith (input, "-L-")) {
		const char *arg = r_str_trim_head_ro (input + 3);
		const int N = atoi (arg);
		R2AI_Messages *messages = r2ai_conversation_get (state);
		if (!messages || r_list_length (messages->messages) == 0) {
			R2_PRINTF ("No conversation history available\n");
		} else {
			r2ai_delete_last_messages (messages, N);
			R2_PRINTF ("Deleted %d message%s from chat history\n", N > 0? N: 1,
				(N > 0 && N != 1)? "s": "");
		}
	} else if (r_str_startswith (input, "-L")) {
		cmd_r2ai_logs (cps);
	} else if (r_str_startswith (input, "-d")) {
		cmd_r2ai_d (cps, r_str_trim_head_ro (input + 2), false);
	} else if (r_str_startswith (input, "-dr")) {
		cmd_r2ai_d (cps, r_str_trim_head_ro (input + 2), true);
	} else if (r_str_startswith (input, "-S")) {
		if (state->db == NULL) {
			state->db = r_vdb_new (R2AI_DEFAULT_VECTORS);
			load_embeddings (cps);
		}
		const char *arg = r_str_trim_head_ro (input + 2);
		const int K = 10;
		RVdbResultSet *rs = r_vdb_query (state->db, arg, K);
		if (rs) {
			int i;
			eprintf ("Found up to %d neighbors (actual found: %d).\n", K, rs->size);
			for (i = 0; i < rs->size; i++) {
				RVdbResult *r = &rs->results[i];
				KDNode *n = r->node;
				R2_PRINTF ("- (%.4f) %s\n", r->dist_sq, n->text);
			}
			r_vdb_result_free (rs);
		}
	} else if (r_str_startswith (input, "-i")) {
		cmd_r2ai_i (cps, r_str_trim_head_ro (input + 2));
	} else if (r_str_startswith (input, "-r")) {
		cmd_r2ai_repl (cps);
	} else if (r_str_startswith (input, "-R")) {
		R2AI_Messages *messages = r2ai_conversation_get (state);
		if (!messages || r_list_length (messages->messages) == 0) {
			R2_PRINTF ("No conversation history to reset\n");
		} else {
			r2ai_msgs_clear (messages);
			R2_PRINTF ("Chat conversation context has been reset\n");
		}
	} else if (r_str_startswith (input, "-Rq")) {
		cmd_r2ai_R (cps, r_str_trim_head_ro (input + 3));
	} else if (r_str_startswith (input, "-m")) {
		cmd_r2ai_m (cps, r_str_trim_head_ro (input + 2));
	} else if (r_str_startswith (input, "-p")) {
		const char *provider = r_str_trim_head_ro (input + 2);
		if (R_STR_ISEMPTY (provider)) {
			R2_PRINTF ("%s\n", r_config_get (core->config, "r2ai.api"));
		} else {
			r_config_set (core->config, "r2ai.api", provider);
		}
	} else if (r_str_startswith (input, "-q")) {
		r2ai_cmd_q (cps, r_str_trim_head_ro (input + 2));
	} else if (r_str_startswith (input, "-")) {
		r_core_cmd_help (core, help_msg_r2ai);
	} else {
		char *err = NULL;
		char *res =
			r2ai (cps, (R2AIArgs){ .input = input, .error = &err, .dorag = true });
		if (err) {
			R_LOG_ERROR ("%s", err);
			R_FREE (err);
		}
		if (res) {
			R2_PRINTF ("%s\n", res);
			free (res);
		}
	}
}

static bool cb_r2ai_api(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		r2ai_list_providers (core, NULL);
		return false;
	}
	// Validate the provider name
	const R2AIProvider *p = r2ai_get_provider (node->value);
	if (p) {
		return true;
	}
	R_LOG_ERROR ("Invalid provider '%s'. Use '?' to list valid providers.", node->value);
	return false;
}

static bool cb_r2ai_model(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	RCore *core = (RCore *)user;
	const char *api = r_config_get (core->config, "r2ai.api");
	if (*node->value == '?') {
		// Try to fetch models dynamically first
		RList *models = r2ai_fetch_available_models (core, api);
		if (models && !r_list_empty (models)) {
			RListIter *iter;
			char *model;
			r_list_foreach (models, iter, model) {
				R2_PRINTLN (model);
			}
			r_list_free (models);
		} else {
			// Fallback to static lists if dynamic fetching fails
			const R2AIProvider *p = r2ai_get_provider (api);
			if (p) {
				if (p->uses_system_ls) {
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
							R2_PRINTLN (item);
						}
						r_list_free (items);
						free (s);
					}
				} else {
					R_LOG_ERROR ("Cannot list models for this provider");
				}
			} else {
				R_LOG_ERROR ("Invalid provider");
			}
		}
		return false;
	}
	return true;
}

R_IPI bool r2ai_init(RCorePluginSession *cps) {
	RCore *core = cps->core;
	// Initialize state
	R2AI_State *state = R_NEW0 (R2AI_State);
	cps->data = state;

	// Initialize conversation container
	r2ai_conversation_init (state);

	char *rc_path = r_file_home (".config/r2ai/rc");
	if (rc_path && r_file_exists (rc_path)) {
		r_core_cmdf (core, ". %s", rc_path);
	}
	free (rc_path);

	r_config_lock (core->config, false);
	r_config_set_cb (core->config, "r2ai.api", R2AI_DEFAULT_PROVIDER, &cb_r2ai_api);
	{
		RStrBuf *sb = r_strbuf_new ("LLM provider to use (");
		r2ai_list_providers (core, sb);
		r_strbuf_append (sb, ")");
		char *desc = r_strbuf_drain (sb);
		r_config_desc (core->config, "r2ai.api", desc);
		free (desc);
	}
	r_config_set_cb (core->config, "r2ai.model", R2AI_DEFAULT_MODEL, &cb_r2ai_model);
	r_config_desc (core->config, "r2ai.model", "Model identifier for the selected provider (e.g. gpt-5-mini)");
	r_config_set (core->config, "r2ai.baseurl", "");
	r_config_desc (core->config, "r2ai.baseurl", "Base URL for provider API (overrides default endpoints)");
	r_config_set_i (core->config, "r2ai.max_tokens", 4096); // max output tokens, or max total tokens
	r_config_desc (core->config, "r2ai.max_tokens", "Maximum tokens for LLM responses (output/total depending on provider)");
	r_config_set_i (core->config, "r2ai.thinking_tokens", 0);
	r_config_desc (core->config, "r2ai.thinking_tokens", "Number of tokens reserved for internal thinking/context messages");
	r_config_set (core->config, "r2ai.temperature", "0.01");
	r_config_desc (core->config, "r2ai.temperature", "Sampling temperature for LLM output (0 = deterministic)");
	r_config_set (core->config, "r2ai.cmds", "pdc");
	r_config_desc (core->config, "r2ai.cmds", "Default command sequence used by automation (e.g. 'pdc')");
	r_config_set (core->config, "r2ai.lang", "C");
	r_config_desc (core->config, "r2ai.lang", "Programming language hint used in prompts (e.g. C, C++, Rust)");
	r_config_set_b (core->config, "r2ai.data", false);
	r_config_desc (core->config, "r2ai.data", "Enable local data/embeddings for query context retrieval");
	r_config_set_b (core->config, "r2ai.data.reason", false);
	r_config_desc (core->config, "r2ai.data.reason", "Include reasoning/explanations from local data when building context");
	r_config_set (core->config, "r2ai.data.path", "/tmp/embeds");
	r_config_desc (core->config, "r2ai.data.path", "Path to local embeddings/text files used for context (one .txt per document)");
	r_config_set_i (core->config, "r2ai.data.nth", 10);
	r_config_desc (core->config, "r2ai.data.nth", "Number of top-matching documents to include from local data for context");
	r_config_set (core->config, "r2ai.hlang", "english");
	r_config_desc (core->config, "r2ai.hlang", "Human language for prompts/messages (e.g. english)");
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
	r_config_set (core->config, "r2ai.promptdir", "~/.config/r2ai/prompts");
	r_config_desc (core->config, "r2ai.promptdir", "Directory containing .r2ai prompt files");
	r_config_set_b (core->config, "r2ai.stream", false);
	r_config_desc (core->config, "r2ai.stream", "Enable streaming responses from the LLM (true/false)");
	r_config_set_i (core->config, "r2ai.auto.max_runs", 50);
	r_config_desc (core->config, "r2ai.auto.max_runs", "Maximum number of automated steps/runs in auto mode");
	r_config_set_b (core->config, "r2ai.auto.hide_tool_output", false);
	r_config_desc (core->config, "r2ai.auto.hide_tool_output", "Hide tool output when running automated actions");
	r_config_set (core->config, "r2ai.auto.init_commands", "iI"); // "aaa;iI;afl~[3]"
	r_config_desc (core->config, "r2ai.auto.init_commands", "Initial commands executed when auto mode starts (semicolon separated)");
	r_config_set_b (core->config, "r2ai.auto.yolo", false);
	r_config_desc (core->config, "r2ai.auto.yolo", "Execute potentially dangerous commands in auto mode without asking");
	r_config_set_b (core->config, "r2ai.auto.reset_on_query", false);
	r_config_desc (core->config, "r2ai.auto.reset_on_query", "Reset auto-mode conversation state on new user queries");
	r_config_set_b (core->config, "r2ai.chat.show_cost", true);
	r_config_desc (core->config, "r2ai.chat.show_cost", "Display estimated API cost for chat interactions");

	r_config_set_i (core->config, "r2ai.http.timeout", 120);
	r_config_desc (core->config, "r2ai.http.timeout", "HTTP client timeout (seconds) for provider API calls");
	r_config_set_i (core->config, "r2ai.http.max_retries", 10);
	r_config_desc (core->config, "r2ai.http.max_retries", "Maximum number of HTTP retries for failed requests");
	r_config_set_i (core->config, "r2ai.http.max_backoff", 30);
	r_config_desc (core->config, "r2ai.http.max_backoff", "Maximum backoff time (seconds) between HTTP retries");
	r_config_set (core->config, "r2ai.http.backend", "auto"); // Options: auto, libcurl, socket, system
	r_config_desc (core->config, "r2ai.http.backend", "HTTP backend to use (auto, libcurl, socket, system)");
	r_config_set_b (core->config, "r2ai.http.use_files", false);
	r_config_desc (core->config, "r2ai.http.use_files", "Use temporary files to pass HTTP request/response payloads (true/false)");
	r_config_set_b (core->config, "r2ai.auto.raw", false);
	r_config_desc (core->config, "r2ai.auto.raw", "Use prompt engineering for tool calling instead of native API support (true/false)");
	r_config_lock (core->config, true);
	return true;
}

R_API bool r2ai_fini(RCorePluginSession *cps) {
	RCore *core = cps->core;
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
	r_config_rm (core->config, "r2ai.http.backend");
	r_config_rm (core->config, "r2ai.http.use_files");
	r_config_lock (core->config, true);

	R2AI_State *state = cps->data;
	r2ai_conversation_free (state);
	r2ai_openai_fini (state);

	if (state) {
		r_vdb_free (state->db);
		state->db = NULL;
		free (state);
		cps->data = NULL;
	}
	return true;
}

static bool r_cmd_r2ai_client(RCorePluginSession *cps, const char *input) {
	if (r_str_startswith (input, "r2ai")) {
		cmd_r2ai (cps, r_str_trim_head_ro (input + 4));
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
		.version = R2AI_VERSION,
		.license = "MIT",
	},
	.init = r2ai_init,
	.fini = r2ai_fini,
	.call = r_cmd_r2ai_client,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_r2ai_client,
	.abiversion = R2_ABIVERSION,
	.version = R2_VERSION
};
#endif
