/* r2ai - Copyright 2023-2024 pancake */

#define R_LOG_ORIGIN "r2ai"

#include "r2ai.h"

static RCoreHelpMessage help_msg_r2ai = {
	"Usage:", "r2ai", " [-args] [...]",
	"r2ai", " -d", "Decompile current function",
	"r2ai", " -dr", "Decompile current function (+ 1 level of recursivity)",
	"r2ai", " -e", "Same as '-e r2ai.'",
	"r2ai", " -h", "Show this help message",
	"r2ai", " -m", "show selected model, list suggested ones, choose one",
	"r2ai", " -M", "show suggested models for each api",
	"r2ai", " -n", "suggest a better name for the current function",
	"r2ai", " -R ([text])", "refresh and query embeddings (see r2ai.data)",
	"r2ai", " -x", "explain current function",
	"r2ai", " -v", "suggest better variables names and types",
	"r2ai", " [arg]", "send a post request to talk to r2ai and print the output",
	NULL
};

static char *r2ai(RCore *core, const char *content, char **error) {
	if (R_STR_ISEMPTY (content)) {
		*error = strdup ("Usage: 'r2ai [query]'. See 'r2ai -h' for help");
		return NULL;
	}
#if 0
	if (!model) {
		*error = strdup ("Model not configured. Use 'r2ai -m provider:model' to set it");
		return NULL;
	}
#endif

	char *model = strdup (r_config_get (core->config, "r2ai.model"));
	char *provider = strdup (r_config_get (core->config, "r2ai.api"));
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
	r_list_foreach (files, iter, file) {
		if (!r_str_endswith (file, ".txt")) {
			continue;
		}
		R_LOG_INFO ("Index %s", file);
		char *filepath = r_file_new (path, file, NULL);
		char *text = r_file_slurp (filepath, NULL);
		if (text) {
			RList *lines = r_str_split_list (text, "\n", -1);
			r_list_foreach (lines, iter2, line) {
				r_vdb_insert (db, line);
				R_LOG_INFO ("Insert %s", line);
			}
			r_list_free (lines);
		}
		free (filepath);
	}
	r_list_free (files);
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
			printf("Query: \"%s\"\n", q);
			printf("Found up to %d neighbors (actual found: %d).\n", K, rs->size);
			for (int i = 0; i < rs->size; i++) {
				RVDBResult *r = &rs->results[i];
				KDNode *n = r->node;
				float dist_sq = r->dist_sq;
				float cos_sim = 1.0f - (dist_sq * 0.5f); // for normalized vectors
				printf("%2d) dist_sq=%.4f cos_sim=%.4f text=\"%s\"\n",
						i + 1, dist_sq, cos_sim, (n->text ? n->text : "(null)"));
			}
			r_vdb_result_free (rs);
		} else {
			printf("No results found (DB empty or error).\n");
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
	if (r_str_startswith (input, "-h")) {
		r_core_cmd_help (core, help_msg_r2ai);
	} else if (r_str_startswith (input, "-e")) {
		const char *arg = r_str_trim_head_ro (input + 2);
		if (r_str_startswith (arg, "r2ai")) {
			r_core_cmdf (core, "-e %s", arg);
		} else {
			r_core_cmdf (core, "-e r2ai.%s", arg);
		}
	} else if (r_str_startswith (input, "-d")) {
		cmd_r2ai_d (core, r_str_trim_head_ro (input + 2), false);
	} else if (r_str_startswith (input, "-dr")) {
		cmd_r2ai_d (core, r_str_trim_head_ro (input + 2), true);
	} else if (r_str_startswith (input, "-x")) {
		cmd_r2ai_x (core);
	} else if (r_str_startswith (input, "-v")) {
		cmd_r2ai_v (core);
	} else if (r_str_startswith (input, "-n")) {
		cmd_r2ai_n (core);
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
