/* query.c - r2ai query prompts */

#include "r2ai.h"

static bool parse_prompt_file(const char *filepath, char **title, char **author, char **desc, char **command, char **prompt, char **requires, char **if_empty, char **if_command) {
	char *content = r_file_slurp (filepath, NULL);
	if (!content) {
		return false;
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
			*title = strdup (value);
		} else if (!strcmp (key, "Author")) {
			*author = strdup (value);
		} else if (!strcmp (key, "Description")) {
			*desc = strdup (value);
		} else if (!strcmp (key, "Command") || !strcmp (key, "Commands")) {
			*command = strdup (value);
		} else if (!strcmp (key, "Prompt") || !strcmp (key, "Query")) {
			*prompt = strdup (value);
		} else if (!strcmp (key, "Requires")) {
			*
				requires
			= strdup (value);
		} else if (!strcmp (key, "If-Empty")) {
			*if_empty = strdup (value);
		} else if (!strcmp (key, "If-Command")) {
			*if_command = strdup (value);
		}
	}
	r_list_free (lines);
	free (content);
	return true;
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
			if (r_str_endswith (file, ".r2ai")) {
				char *name = r_str_ndup (file, strlen (file) - 5);
				char *filepath = r_str_newf ("%s/%s.r2ai", expanded_dir, name);
				char *title = NULL, *author = NULL, *desc = NULL, *command = NULL, *prompt = NULL, *
					requires
				= NULL, *if_empty = NULL, *if_command = NULL;
				if (parse_prompt_file (filepath, &title, &author, &desc, &command, &prompt, &requires, &if_empty, &if_command)) {
					R2_PRINTF ("%s: %s - %s\n", name, title? title: "", desc? desc: "");
				} else {
					R2_PRINTLN (name);
				}
				free (name);
				free (filepath);
				free (title);
				free (author);
				free (desc);
				free (command);
				free (prompt);
				free (requires);
				free (if_empty);
				free (if_command);
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
		char *filepath = r_str_newf ("%s/%s.r2ai", expanded_dir, name);
		char *title = NULL, *author = NULL, *desc = NULL, *command = NULL, *prompt = NULL, *
			requires
		= NULL, *if_empty = NULL, *if_command = NULL;
		if (!parse_prompt_file (filepath, &title, &author, &desc, &command, &prompt, &requires, &if_empty, &if_command)) {
			R_LOG_ERROR ("Cannot read prompt file: %s", filepath);
			free (filepath);
			free (name);
			return;
		}
		if (!title || !command) {
			R_LOG_WARN ("Prompt %s is missing required Title or Command directive", name);
		}
		free (filepath);
		// run commands
		char *cmd_output = run_commands (core, command);
		// run if_command if output not empty
		if (cmd_output && *cmd_output && if_command) {
			char *extra_out = run_commands (core, if_command);
			if (extra_out) {
				char *new_output = r_str_newf ("%s\n%s", cmd_output, extra_out);
				free (cmd_output);
				cmd_output = new_output;
				free (extra_out);
			}
		}
		// determine the prompt to use
		char *use_prompt = prompt;
		if ((!cmd_output || !*cmd_output) && if_empty) {
			use_prompt = if_empty;
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
		free (title);
		free (author);
		free (desc);
		free (command);
		free (prompt);
		free (requires);
		free (if_empty);
		free (if_command);
		free (name);
	}
	free (expanded_dir);
}
