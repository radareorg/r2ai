/* Copyright r2ai - 2023-2026 - pancake */

#include "r2ai_priv.h"

#define CLIPPY "?E"
// #define CLIPPY "?EC" // pico le croco

static void show_help() {
	printf (
		"Usage: r2ai [-vhdorEwK] [-p provider] [-m model] [-q query]\n"
		"            [-b url] [-c command] [-f file] [-s addr]\n"
		"            [-i script] [-e var=value] [prompt]\n"
		"  -v           Show version information\n"
		"  -h           Show this help message\n"
		"  -d           Decompile current function\n"
		"  -d <query>   Ask a question on the current function\n"
		"  -do          Decompile current function with source offsets\n"
		"  -dr          Decompile current function recursively\n"
		"  -p <provider> Select LLM provider\n"
		"  -m <model>   Select LLM model\n"
		"  -q <query>   Execute predefined prompt query (can be used multiple times)\n"
		"  -qj          List predefined prompt queries as JSON\n"
		"  -b <url>     Set base URL for provider API\n"
		"  -c <command> Execute command after loading file (can be used multiple times)\n"
		"  -f <file>    Load file with r2 API\n"
		"  -s <addr>    Seek to address after loading file\n"
		"  -i <script>  Load and interpret script file before executing commands\n"
		"  -e <var=value> Set configuration variable\n"
		"  -E           Edit the r2ai rc file\n"
		"  -K           Edit the API keys file\n"
		"  -w           Launch interactive setup wizard\n");
}

static void show_version() {
	printf ("r2ai " R2AI_VERSION "\n");
}

static char *join_argv(int argc, const char **argv, int start) {
	if (start >= argc) {
		return strdup ("");
	}
	int i;
	RStrBuf *sb = r_strbuf_new ("");
	for (i = start; i < argc; i++) {
		if (i > start) {
			r_strbuf_append (sb, " ");
		}
		r_strbuf_append (sb, argv[i]);
	}
	return r_strbuf_drain (sb);
}

static char *build_conversation(RList *conversation) {
	RListIter *iter;
	char *msg;
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (conversation, iter, msg) {
		r_strbuf_appendf (sb, "%s\n", msg);
	}
	return r_strbuf_drain (sb);
}

static void r2ai_repl(RCorePluginSession *cps, const char *provider, const char *model, RList *conversation) {
	RCore *core = cps->core;
	r2ai_wizard_autorun (core);
	r_line_set_prompt (core->cons->line, "[r2ai]> ");
	while (true) {
		const char *input = r_line_readline (core->cons);
		if (r_cons_is_breaked (core->cons) || R_STR_ISEMPTY (input)) {
			break;
		}
		if (input[0] == '!') {
			// Execute shell command
			system (input + 1);
		} else if (input[0] == ':') {
			// Run radare2 command
			char *res = r_core_cmd_str (core, input + 1);
			if (res) {
				r_cons_println (core->cons, res);
				free (res);
			}
		} else if (input[0] == 'q') {
			if (r_cons_yesno (core->cons, 'y', "Do you want to quit? (Y/n)")) {
				break;
			}
		} else if (input[0] == '-') {
			cmd_r2ai (cps, input);
		} else {
			// Send message to LLM as part of conversation
			r_list_append (conversation, r_str_newf ("User: %s", input));
			char *full_prompt = build_conversation (conversation);
			char *err = NULL;
			R2AIArgs args = {
				.input = full_prompt,
				.provider = provider,
				.model = model,
				.error = &err,
				.dorag = false,
};
			char *res = r2ai (cps, args);
			if (res) {
				if (r_config_get_b (core->config, "r2ai.clippy")) {
					char *cmd = r_str_newf (CLIPPY " %s", res);
					r_core_call (core, cmd);
					free (cmd);
				} else {
					r_cons_println (core->cons, res);
					r_list_append (conversation, r_str_newf ("Assistant: %s", res));
				}
				free (res);
			}
			if (err) {
				r_cons_println (core->cons, err);
				free (err);
			}
			free (full_prompt);
		}
		r_cons_flush (core->cons);
	}
}

int main(int argc, const char **argv) {
	int c;
	const char *provider = NULL;
	const char *model = NULL;
	const char *baseurl = NULL;
	const char *filename = NULL;
	const char *seekaddr = NULL;
	const char *scriptfile = NULL;
	bool list_queries_json = false;
	bool decompile = false;
	bool decompile_recursive = false;
	bool decompile_offsets = false;
	RList *conversation = r_list_newf (free);
	RList *queries = r_list_newf (free);
	RList *commands = r_list_newf (free);
	RCore *core = r_core_new ();
	RCorePluginSession cps = {
		.core = core
	};
	r2ai_init (&cps);

	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "vhdorp:m:q:Eb:Kc:f:s:i:e:w");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'd':
			decompile = true;
			break;
		case 'o':
			if (!decompile) {
				show_help ();
				goto beach;
			}
			decompile_offsets = true;
			break;
		case 'r':
			if (!decompile) {
				show_help ();
				goto beach;
			}
			decompile_recursive = true;
			break;
		case 'p':
			provider = opt.arg;
			break;
		case 'm':
			model = opt.arg;
			break;
		case 'q':
			if (!strcmp (opt.arg, "j")) {
				list_queries_json = true;
			} else {
				r_list_append (queries, strdup (opt.arg));
			}
			break;
		case 'b':
			baseurl = opt.arg;
			break;
		case 'c':
			r_list_append (commands, strdup (opt.arg));
			break;
		case 'f':
			filename = opt.arg;
			break;
		case 's':
			seekaddr = opt.arg;
			break;
		case 'i':
			scriptfile = opt.arg;
			break;
		case 'e':
			{
				char *var_value = strdup (opt.arg);
				char *equals = strchr (var_value, '=');
				if (equals) {
					*equals = '\0';
					const char *var = var_value;
					const char *value = equals + 1;
					r_config_set (core->config, var, value);
				} else {
					r_cons_println (core->cons, "Invalid format for -e. Use var=value.");
				}
				free (var_value);
			}
			break;
		case 'E':
			{
				char *rc_path = r_file_home (".config/r2ai/rc");
				r_cons_editor (core->cons, rc_path, NULL);
				free (rc_path);
				goto beach;
			}
			break;
		case 'K':
			{
				r2ai_apikeys_edit (&cps);
				goto beach;
			}
			break;
		case 'w':
			{
				r2ai_wizard (core);
				goto beach;
			}
			break;
		case 'v':
			show_version ();
			goto beach;
		case 'h':
			show_help ();
			goto beach;
		default:
			show_help ();
			goto beach;
		}
	}

	if (list_queries_json) {
		r2ai_cmd_qj (&cps, NULL);
		r_cons_flush (core->cons);
		goto beach;
	}
	if (decompile && decompile_offsets && decompile_recursive) {
		r_cons_println (core->cons, "Cannot combine -do and -dr.");
		r_cons_flush (core->cons);
		goto beach;
	}

	if (baseurl) {
		r_config_set (core->config, "r2ai.baseurl", baseurl);
	}
	if (filename) {
		char *cmd = r_str_newf ("o %s", filename);
		r_core_call (core, cmd);
		free (cmd);
		// TODO: use the C api instead of the 'o' command and check for error if file exists etc
		if (seekaddr) {
			char *seekcmd = r_str_newf ("s %s", seekaddr);
			r_core_call (core, seekcmd);
			free (seekcmd);
		}
	} else {
		r_core_cmd0 (core, CLIPPY " Interesting, no files to analyse. Use -f or :o");
		r_cons_flush (core->cons);
	}
	if (scriptfile) {
		char *cmd = r_str_newf (". %s", scriptfile);
		r_core_call (core, cmd);
		free (cmd);
	}
	if (!r_list_empty (commands)) {
		RListIter *iter;
		char *cmd;
		r_list_foreach (commands, iter, cmd) {
			char *res = r_core_cmd_str (core, cmd);
			if (res) {
				r_cons_println (core->cons, res);
				free (res);
			}
		}
	}
	r_config_set_b (core->config, "r2ai.utf8", false);
	r_config_set_b (core->config, "r2ai.clippy", true);
	if (provider) {
		r_config_set (core->config, "r2ai.api", provider);
	}
	if (model) {
		r_config_set (core->config, "r2ai.model", model);
	}
	if (decompile) {
		const char *dflag = decompile_offsets? "-do": (decompile_recursive? "-dr": "-d");
		char *query = join_argv (argc, argv, opt.ind);
		char *dcmd = R_STR_ISNOTEMPTY (query)? r_str_newf ("%s %s", dflag, query): strdup (dflag);
		cmd_r2ai (&cps, dcmd);
		r_cons_flush (core->cons);
		free (dcmd);
		free (query);
		goto beach;
	}

	// Process queries if any
	if (!r_list_empty (queries)) {
		RListIter *iter;
		char *query;
		r_list_foreach (queries, iter, query) {
			r2ai_cmd_q (&cps, query);
		}
	} else {
		if (opt.ind >= argc) {
			r2ai_repl (&cps, provider, model, conversation);
		} else {
			const char *prompt = argv[opt.ind];

			char *err = NULL;
			R2AIArgs args = {
				.input = prompt,
				.provider = provider,
				.model = model,
				.error = &err,
				.dorag = false,
};
			char *res = r2ai (&cps, args);
			if (res) {
				r_cons_println (core->cons, res);
				free (res);
			}
			free (err);
			r_cons_flush (core->cons);
		}
	}

beach:
	r_list_free (conversation);
	r_list_free (queries);
	r_list_free (commands);
	r2ai_fini (&cps);
	r_core_free (core);
	return 0;
}
