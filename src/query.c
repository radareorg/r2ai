/* r2ai - Copyright 2023-2025 pancake */

#include "r2ai.h"

static R2AIPrompt *parse_prompt_file(const char *filepath) {
	R2AIPrompt *prompt = R_NEW0 (R2AIPrompt);
	char *content = r_file_slurp (filepath, NULL);
	if (!content) {
		free (prompt);
		return NULL;
	}
	RList *lines = r_str_split_list (content, "\n", -1);
	RListIter *iter;
	char *line;
	r_list_foreach (lines, iter, line) {
		r_str_trim (line);
		if (*line == '#' || *line == 0) {
			continue;
		}
		char *colon = strchr (line, ':');
		if (!colon) {
			continue;
		}
		*colon = 0;
		char *key = line;
		char *value = colon + 1;
		r_str_trim (key);
		r_str_trim (value);
		if (!strcmp (key, "Title")) {
			prompt->title = strdup (value);
		} else if (!strcmp (key, "Author")) {
			prompt->author = strdup (value);
		} else if (!strcmp (key, "Description")) {
			prompt->desc = strdup (value);
		} else if (!strcmp (key, "Command") || !strcmp (key, "Commands")) {
			prompt->command = strdup (value);
		} else if (!strcmp (key, "Prompt") || !strcmp (key, "Query")) {
			prompt->prompt = strdup (value);
		} else if (!strcmp (key, "Depends")) {
			prompt->
				requires
			= strdup (value);
		} else if (!strcmp (key, "If-Empty")) {
			prompt->if_empty = strdup (value);
		} else if (!strcmp (key, "If-Command")) {
			prompt->if_command = strdup (value);
		}
	}
	r_list_free (lines);
	free (content);
	return prompt;
}

static char *run_commands(RCore *core, const char *commands) {
	if (!commands) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	char *cmds_str = strdup (commands);
	RList *cmds = r_str_split_list (cmds_str, ";", -1);
	RListIter *iter;
	char *cmd;
	r_list_foreach (cmds, iter, cmd) {
		r_str_trim (cmd);
		if (*cmd) {
			char *out = r_core_cmd_str (core, cmd);
			r_strbuf_append (sb, out);
			free (out);
		}
	}
	r_list_free (cmds);
	free (cmds_str);
	return r_strbuf_drain (sb);
}

static char *replace_vars(RCore *core, const char *text) {
	if (!text) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	const char *p = text;
	while (*p) {
		if (*p == '$' && *(p + 1) == '{') {
			p += 2;
			const char *end = strchr (p, '}');
			if (end) {
				char *var = r_str_ndup (p, end - p);
				char *val = getenv (var);
				if (val) {
					r_strbuf_append (sb, val);
				}
				free (var);
				p = end + 1;
			} else {
				r_strbuf_append (sb, "${");
				p += 2;
			}
		} else if (*p == '$' && *(p + 1) == '(') {
			p += 2;
			const char *end = strchr (p, ')');
			if (end) {
				char *cmd = r_str_ndup (p, end - p);
				char *val = r_core_cmd_str (core, cmd);
				r_str_trim (val);
				r_strbuf_append (sb, val);
				free (val);
				free (cmd);
				p = end + 1;
			} else {
				r_strbuf_append (sb, "$(");
				p += 2;
			}
		} else {
			r_strbuf_append_n (sb, p, 1);
			p++;
		}
	}
	return r_strbuf_drain (sb);
}

void cmd_r2ai_q(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	const char *promptdir = r_config_get (core->config, "r2ai.promptdir");
	if (!promptdir || !*promptdir) {
		promptdir = "~/.config/r2ai/prompts";
	}
	char *expanded_dir = r_file_abspath (promptdir);
	if (!r_file_is_directory (expanded_dir)) {
		R_LOG_ERROR ("Prompt directory does not exist: %s", expanded_dir);
		free (expanded_dir);
		return;
	}
	if (!input || !*input) {
		// list prompts
		RList *files = r_sys_dir (expanded_dir);
		RListIter *iter;
		char *file;
		r_list_foreach (files, iter, file) {
			if (r_str_endswith (file, ".r2ai.txt")) {
				char *dot = strchr (file, '.');
				char *name = dot? r_str_ndup (file, dot - file): strdup (file);
				char *filepath = r_str_newf ("%s/%s.r2ai.txt", expanded_dir, name);
				R2AIPrompt *prompt = parse_prompt_file (filepath);
				if (prompt) {
					R2_PRINTF ("%s: %s - %s\n", name, prompt->title? prompt->title: "", prompt->desc? prompt->desc: "");
					free (prompt->title);
					free (prompt->author);
					free (prompt->desc);
					free (prompt->command);
					free (prompt->prompt);
					free (prompt->requires);
					free (prompt->if_empty);
					free (prompt->if_command);
					free (prompt);
				} else {
					R2_PRINTLN (name);
				}
				free (name);
				free (filepath);
			}
		}
		r_list_free (files);
	} else {
		// run prompt
		char *name = strdup (input);
		char *extra = strchr (name, ' ');
		if (extra) {
			*extra++ = 0;
			r_str_trim (extra);
		}
		r_str_trim (name);
		char *filepath = r_str_newf ("%s/%s.r2ai.txt", expanded_dir, name);
		R2AIPrompt *prompt = parse_prompt_file (filepath);
		if (!prompt) {
			R_LOG_ERROR ("Cannot read prompt file: %s", filepath);
			free (filepath);
			free (name);
			return;
		}
		if (!prompt->title || !prompt->command) {
			R_LOG_WARN ("Prompt %s is missing required Title or Command directive", name);
		}
		free (filepath);
		// run commands
		char *cmd_output = run_commands (core, prompt->command);
		// run if_command if output not empty
		if (cmd_output && *cmd_output && prompt->if_command) {
			char *extra_out = run_commands (core, prompt->if_command);
			if (extra_out) {
				char *new_output = r_str_newf ("%s\n%s", cmd_output, extra_out);
				free (cmd_output);
				cmd_output = new_output;
				free (extra_out);
			}
		}
		// determine the prompt to use
		char *use_prompt = prompt->prompt;
		if ((!cmd_output || !*cmd_output) && prompt->if_empty) {
			use_prompt = prompt->if_empty;
		}
		// replace vars in prompt
		char *replaced_prompt = replace_vars (core, use_prompt);
		RStrBuf *sb = r_strbuf_new (replaced_prompt);
		free (replaced_prompt);
		if (cmd_output) {
			r_strbuf_appendf (sb, "\n%s", cmd_output);
			free (cmd_output);
		}
		if (extra) {
			r_strbuf_appendf (sb, "\n%s", extra);
		}
		char *final_prompt = r_strbuf_drain (sb);
		// now send to LLM
		char *error = NULL;
		char *res = r2ai (core, state, (R2AIArgs){ .input = final_prompt, .error = &error, .dorag = true });
		if (error) {
			R_LOG_ERROR ("%s", error);
			free (error);
		} else if (res) {
			R2_PRINTF ("%s\n", res);
			free (res);
		}
		free (final_prompt);
		free (prompt->title);
		free (prompt->author);
		free (prompt->desc);
		free (prompt->command);
		free (prompt->prompt);
		free (prompt->requires);
		free (prompt->if_empty);
		free (prompt->if_command);
		free (prompt);
		free (name);
	}
	free (expanded_dir);
}
