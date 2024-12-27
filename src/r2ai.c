/* radare - Copyright 2023-2024 pancake */

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
	"r2ai", " -x", "explain current function",
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
