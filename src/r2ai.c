/* r2ai - Copyright 2023-2025 pancake */

#define R_LOG_ORIGIN "r2ai"

#include "r2ai.h"
static R_TH_LOCAL RVDB *db = NULL;

static void refresh_embeddings(RCore *core) {
	// refresh embeddings database
	if (db) {
		r_vdb_free (db);
	}
	db = r_vdb_new (4);
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


static RCoreHelpMessage help_msg_r2ai = {
	"Usage:", "r2ai", " [-args] [...]",
	"r2ai", " -d", "Decompile current function",
	"r2ai", " -dr", "Decompile current function (+ 1 level of recursivity)",
	"r2ai", " -a [query]", "Resolve question using auto mode",
	"r2ai", " -e", "Same as '-e r2ai.'",
	"r2ai", " -h", "Show this help message",
	"r2ai", " -i [file] [query]", "read file and ask the llm with the given query",
	"r2ai", " -m", "show selected model, list suggested ones, choose one",
	"r2ai", " -M", "show suggested models for each api",
	"r2ai", " -n", "suggest a better name for the current function",
	"r2ai", " -r", "enter the repl",
	"r2ai", " -R ([text])", "refresh and query embeddings (see r2ai.data)",
	"r2ai", " -s", "function signature",
	"r2ai", " -x", "explain current function",
	"r2ai", " -v", "suggest better variables names and types",
	"r2ai", " -V[r]", "find vulnerabilities in the decompiled code (-Vr uses -dr)",
	"r2ai", " [arg]", "send a post request to talk to r2ai and print the output",
	NULL
};

R_IPI char *r2ai(RCore *core, const char *input, char **error) {
	if (R_STR_ISEMPTY (input)) {
		*error = strdup ("Usage: 'r2ai [query]'. See 'r2ai -h' for help");
		return NULL;
	}
#if 0
	if (!model) {
		*error = strdup ("Model not configured. Use 'r2ai -m provider:model' to set it");
		return NULL;
	}
#endif

	char *content = strdup (input);
	char *model = strdup (r_config_get (core->config, "r2ai.model"));
	char *provider = strdup (r_config_get (core->config, "r2ai.api"));
	if (r_config_get_b (core->config, "r2ai.data")) {
		if (!db) {
			refresh_embeddings (core);
		}
		const int K = r_config_get_i (core->config, "r2ai.data.nth");
		RVDBResultSet *rs = r_vdb_query (db, input, K);

		if (rs) {
			//printf("Found up to %d neighbors (actual found: %d).\n", K, rs->size);
			RStrBuf *sb = r_strbuf_new (".\nConsider:\n");
			for (int i = 0; i < rs->size; i++) {
				RVDBResult *r = &rs->results[i];
				KDNode *n = r->node;
				r_strbuf_appendf (sb, "- %s\n", n->text);
			}
			char *s = r_strbuf_drain (sb);
			free (content);
			content = r_str_newf ("%s%s", input, s);
			free (s);
			r_vdb_result_free (rs);
		}
	}
#if 0
	if (!strstr (provider, "ollama")) {
		free (provider);
		provider = strdup (model);
		char *colon = strchr (provider, ':');
		if (colon) {
			*colon = 0;
			free (model);
			model = strdup (colon + 1);
		}
	}
	R_LOG_INFO ("Model: %s", model);
	R_LOG_INFO ("Provider: %s", provider);
#endif
	// free (model);
	bool stream = r_config_get_b (core->config, "r2ai.stream");
	char *result = NULL;
	if (R_STR_ISEMPTY (model)) {
		R_FREE (model);
	}
#if 0
	// r2ai.debug
	eprintf ("====\n");
	eprintf ("%s\n", content);
	eprintf ("====\n");
#endif
	if (!strcmp (provider, "openapi")) {
		result = r2ai_openapi (content, error);
	} else if (!strcmp (provider, "ollama")) {
		result = r2ai_ollama (core, content, model, error);
#if R2_VERSION_NUMBER >= 50909
	} else if (!strcmp (provider, "openai")) {
		result = stream
			? r2ai_openai_stream (core, content, model, error)
			: r2ai_openai (core, content, model, error);
	} else if (!strcmp (provider, "xai")) {
		result = stream
			? r2ai_xai_stream (core, content, error)
			: r2ai_xai (core, content, error);
	} else if (!strcmp (provider, "anthropic") || !strcmp (provider, "claude")) {
		result = stream
			? r2ai_anthropic_stream (content, model, error)
			: r2ai_anthropic (content, model, error);
	} else if (!strcmp (provider, "gemini")) {
		result = stream
			? r2ai_gemini_stream (content, model, error)
			: r2ai_gemini (content, model, error);
	} else {
		*error = strdup ("Unsupported provider. Use openapi, ollama, openai, xai, gemini, anthropic");
#else
	} else {
		*error = strdup ("Unsupported provider. Use openapi, ollama");
#endif
	}
	
	free (provider);
	return result;
}

static void cmd_r2ai_d(RCore *core, const char *input, const bool recursive) {
	const bool r2ai_stream = r_config_get_b (core->config, "r2ai.stream");
	r_config_set_b (core->config, "r2ai.stream", false);
	const char *prompt = r_config_get (core->config, "r2ai.prompt");
	char *cmds = strdup (r_config_get (core->config, "r2ai.cmds"));
	RStrBuf *sb = r_strbuf_new (prompt);
	RList *cmdslist = r_str_split_list (cmds, ",", -1);
	RListIter *iter;
	const char *cmd;
	RList *refslist = NULL;
	if (recursive) {
		char *refs = r_core_cmd_str (core, "axff~^C[2]~$$");
		refslist = r_str_split_list (refs, ",", -1);
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
	char *res = r2ai (core, s, &error);
	free (s);
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		r_cons_printf ("%s\n", res);
	}
	free (res);
	r_list_free (cmdslist);
	r_config_set_b (core->config, "r2ai.stream", r2ai_stream);
}

static void cmd_r2ai_x(RCore *core) {
	const char *hlang = r_config_get (core->config, "r2ai.hlang");
	char *explain_prompt = r_str_newf ("Analyze function calls, comments and strings, ignore registers and memory accesess. Considering the references and involved loops make explain the purpose of this function in one or two short sentences. Output must be only the translation of the explanation in %s", hlang);
	char *s = r_core_cmd_str (core, "r2ai -d");
	char *error = NULL;
	char *q = r_str_newf ("%s\n[CODE]\n%s\n[/CODE]\n", explain_prompt, s);
	char *res = r2ai (core, q, &error);
	free (s);
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		r_cons_printf ("%s\n", res);
	}
	free (res);
	free (q);
	free (explain_prompt);
}

static void cmd_r2ai_R(RCore *core, const char *q) {
	if (R_STR_ISEMPTY (q)) {
		if (db) {
			r_vdb_free (db);
			db = NULL;
		}
		refresh_embeddings (core);
	} else {
		if (!db) {
			refresh_embeddings (core);
		}
		const int K = r_config_get_i (core->config, "r2ai.data.nth");
		RVDBResultSet *rs = r_vdb_query (db, q, K);

		if (rs) {
			R_LOG_INFO ("Query: \"%s\"", q);
			R_LOG_INFO ("Found up to %d neighbors (actual found: %d)", K, rs->size);
			int i;
			for (i = 0; i < rs->size; i++) {
				RVDBResult *r = &rs->results[i];
				KDNode *n = r->node;
				float dist_sq = r->dist_sq;
				float cos_sim = 1.0f - (dist_sq * 0.5f); // for normalized vectors
				printf ("%2d) dist_sq=%.4f cos_sim=%.4f text=\"%s\"\n",
						i + 1, dist_sq, cos_sim, (n->text ? n->text : "(null)"));
			}
			r_vdb_result_free (rs);
		} else {
			R_LOG_ERROR ("No vdb results found");
		}
	}
}

static void cmd_r2ai_n(RCore *core) {
	char *s = r_core_cmd_str (core, "r2ai -d");
	char *q = r_str_newf ("output only the radare2 commands in plain text without markdown. Give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: \n```c\n%s\n```", s);
	char *error = NULL;
	char *res = r2ai (core, q, &error);
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
		free (fname);
		R_LOG_ERROR ("Cannot open %s", fname);
		return;
	}
	char *q = r_str_newf ("%s\n```\n%s\n```\n", query, s);
	char *error = NULL;
	char *res = r2ai (core, q, &error);
	free (s);
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		r_cons_printf ("%s\n", res);
	}
	free (fname);
	free (s);
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
	char *q = r_str_newf ("analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the resturn. Do NOT print the function body, ONLY output the function signature, ignore '@' in argument types because it must be used in a C header:\n```\n%s\n``` source code:\n```\n%s\n```\n", afv, s);
	char *error = NULL;
	char *res = r2ai (core, q, &error);
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
	char *q = r_str_newf ("Output only the radare2 command without markdown, guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands:\n```\n%s```", afv);
	char *error = NULL;
	char *res = r2ai (core, q, &error);
	if (error) {
		R_LOG_ERROR (error);
		free (error);
	} else {
		r_cons_printf ("%s\n", res);
	}
	free (afv);
	free (res);
	free (q);
	free (s);
}

static void cmd_r2ai_V(RCore *core, bool recursive) {
	char *s = r_core_cmd_str (core, recursive? "r2ai -d": "r2ai -dr");
	char *q = r_str_newf ("find vulnerabilities, dont show the code, only show the response, provide a sample exploit and suggest good practices:\n```\n%s```", s);
	char *error = NULL;
	char *res = r2ai (core, q, &error);
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

static void cmd_r2ai_M(RCore *core) {
	r_cons_printf ("r2ai -e api=anthropic\n");
	r_cons_printf ("-m claude-3-5-sonnet-20241022\n");
	r_cons_printf ("-m claude-3-haiku-20240307\n");
	r_cons_printf ("r2ai -e api=gemini\n");
	r_cons_printf ("-m gemini-1.5-flash\n");
	r_cons_printf ("-m gemini-1.0-pro\n");
	r_cons_printf ("r2ai -e api=openai\n");
	r_cons_printf ("-m gpt-4\n");
	r_cons_printf ("-m gpt-3.5-turbo\n");
	r_cons_printf ("r2ai -e api=ollama\n");
	r_cons_printf ("-m llama3.2:1b\n");
	r_cons_printf ("-m llama3\n");
	r_cons_printf ("-m codegeex4\n");
	r_cons_printf ("-m qwen2.5-coder:3b\n");
	r_cons_printf ("-m benevolentjoker/nsfwvanessa\n");
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
	} else if (r_str_startswith (input, "-d")) {
		cmd_r2ai_d (core, r_str_trim_head_ro (input + 2), false);
	} else if (r_str_startswith (input, "-dr")) {
		cmd_r2ai_d (core, r_str_trim_head_ro (input + 2), true);
	} else if (r_str_startswith (input, "-x")) {
		cmd_r2ai_x (core);
	} else if (r_str_startswith (input, "-s")) {
		cmd_r2ai_s (core);
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
		cmd_r2ai_R (core, r_str_trim_head_ro (input + 2));
	} else if (r_str_startswith (input, "-M")) {
		cmd_r2ai_M (core);
	} else if (r_str_startswith (input, "-m")) {
		cmd_r2ai_m (core, r_str_trim_head_ro (input + 2));
	} else if (r_str_startswith (input, "-")) {
		r_core_cmd_help (core, help_msg_r2ai);
	} else {
		char *err = NULL;
		char *res = r2ai (core, input, &err);
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

static int r2ai_init(void *user, const char *input) {
	RCmd *cmd = (RCmd*)user;
	RCore *core = cmd->data;
	r_config_lock (core->config, false);
	r_config_set (core->config, "r2ai.api", "ollama");
	r_config_set (core->config, "r2ai.model", ""); // "qwen2.5-coder:3b"); // qwen2.5-4km");
	r_config_set (core->config, "r2ai.cmds", "pdc");
	r_config_set (core->config, "r2ai.lang", "C");
	r_config_set_b (core->config, "r2ai.data", "false");
	r_config_set (core->config, "r2ai.data.path", "/tmp/embeds");
	r_config_set_i (core->config, "r2ai.data.nth", 10);
	r_config_set (core->config, "r2ai.hlang", "english");
	r_config_set (core->config, "r2ai.system", "Your name is r2clippy");
	r_config_set (core->config, "r2ai.prompt", "Rewrite this function and respond ONLY with code, replace goto/labels with if/else/for, use NO explanations, NO markdown, Simplify as much as possible, use better variable names, take function arguments and and strings from comments like 'string:'");
	r_config_set_b (core->config, "r2ai.stream", false);
	r_config_lock (core->config, true);
	return true;
}

static int r2ai_fini(void *user, const char *input) {
	RCmd *cmd = (RCmd*)user;
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
	r_config_lock (core->config, true);
	return true;
}

static int r_cmd_r2ai_client(void *user, const char *input) {
	RCore *core = (RCore *) user;
	r_sys_setenv ("R2_CURL", "1");
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
		.version = "0.9.4",
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
	.version = R2_VERSION
};
#endif
