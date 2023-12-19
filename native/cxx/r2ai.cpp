/* radare - Copyright 2023 - pancake */

#define R_LOG_ORIGIN "r2ai"

#include <r_core.h>
#include "common.h"

#define R2AI_HELP_MESSAGE \
"Usage: r2ai [-option] ([query] | [script.py])\n"\
" r2ai . [file]          interpret r2ai script with access to globals\n"\
" r2ai :aa               run a r2 command\n"\
" r2ai !ls               run a system command\n"\
" r2ai -a                query with audio voice\n"\
" r2ai -A                enter the voice chat loop\n"\
" r2ai -k                clear the screen\n"\
" r2ai -c [cmd] [query]  run the given r2 command with the given query\n"\
" r2ai -e [k[=v]]        set environment variable\n"\
" r2ai -f [file]         load file and paste the output\n"\
" r2ai -h                show this help\n"\
" r2ai -i [file] [query] load the file contents and prompt it with the given query\n"\
" r2ai -m [file/repo]    select model from huggingface repository or local file\n"\
" r2ai -M                list supported and most common models from hf\n"\
" r2ai -n [num]          select the nth language model\n"\
" r2ai -q                quit/exit/^C\n"\
" r2ai -L                show chat logs\n"\
" r2ai -r [sysprompt]    define the role of the conversation\n"\
" r2ai -r2               enter the r2clippy assistant mode\n"\
" r2ai -rf [doc/role/.f] load contents of a file to define the role\n"\
" r2ai -R                reset the chat conversation context\n"\
" r2ai -t [temp]         from 0.0001 to 10 your scale to randomness in my replies\n"\
" r2ai -v                show r2ai version\n"\
" r2ai -w                toggle including LLM responses into the query (False is faster)\n"

static void r2ai_parseflag(RCore *core, const char *input) {
	switch (*input) {
	case 'v':
		r_cons_printf ("r2ai-native-v0.1\n");
#if 0
		r_cons_printf ("%s: build = %d (%s)\n",      __func__, LLAMA_BUILD_NUMBER, LLAMA_COMMIT);
		r_cons_printf ("%s: built with %s for %s\n", __func__, LLAMA_COMPILER, LLAMA_BUILD_TARGET);
#endif
		break;
	default:
		R_LOG_ERROR ("Unknown flag");
		break;
	}
}

static void r2ai_init(RCore *core) {
}

extern int main_r2ai_message(const char *message);
extern bool main_r2ai_init(const char *model_path);

static void r2ai_message(RCore *core, const char *input) {
	const char *model_path = r_config_get (core->config, "r2ai.model");
	main_r2ai_init (model_path);
	const char *prompt = "Act as a radare2 assistant named r2ai";
	const char *prompt_reply = "Sure!";
	char *s = r_str_newf ("<s>[INST]%s[/INST]%s</s>%s", prompt, prompt_reply, input);
	main_r2ai_message (input);
	free (s);
	r2ai_init (core);
}

static int r_cmd_r2ai_init(void *user, const char *input) {
	RCmd *rcmd = (RCmd*)user;
	RCore *core = (RCore *) rcmd->data;
	if (core) {
		RConfig *cfg = core->config;
		r_config_lock (cfg, false);
		r_config_set (cfg, "r2ai.model", "/tmp/mistral-7b-v0.1.Q2_K.gguf");
		r_config_set (cfg, "r2ai.temp", "0.02");
		r_config_lock (cfg, true);
	} else {
		R_LOG_INFO ("Can't init");
	}
	return true;
}

static int r_cmd_r2ai_fini(void *user, const char *input) {
	RCmd *rcmd = (RCmd*)user;
	RCore *core = (RCore *) rcmd->data;
	if (core) {
		RConfig *cfg = core->config;
		r_config_lock (cfg, false);
		r_config_rm (cfg, "r2ai.model");
		r_config_rm (cfg, "r2ai.temp");
		r_config_lock (cfg, true);
	} else {
		R_LOG_INFO ("Can't init");
	}
	return true;
}

static int r_cmd_r2ai_native(void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (r_str_startswith (input, "r2ai")) {
		if (input[4] == ' ') {
			const char *arg = r_str_trim_head_ro (input + 4);
			if (*arg == '-') {
				r2ai_parseflag (core, arg + 1);
			} else {
				r2ai_message (core, r_str_trim_head_ro (arg));
			}
		} else {
			r_cons_printf (R2AI_HELP_MESSAGE);
		}
		return true;
	}
	return false;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_hello = {
	.meta = {
		.name = (char *)"r2ai-native",
		.desc = (char *)"native r2ai plugin",
		.author = (char *)"pancake",
		.license = (char *)"MIT",
	},
	.call = r_cmd_r2ai_native,
	.init = r_cmd_r2ai_init,
	.fini = r_cmd_r2ai_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_hello,
	.version = R2_VERSION
};
#endif
