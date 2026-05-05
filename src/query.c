/* r2ai - Copyright 2023-2026 pancake */

#include "r2ai.h"

R_API void r2aiprompt_free(R2AIPrompt *prompt) {
	if (!prompt) {
		return;
	}
	free (prompt->title);
	free (prompt->author);
	free (prompt->desc);
	free (prompt->command);
	free (prompt->prompt);
	free (prompt->requires);
	free (prompt->if_empty);
	free (prompt->if_command);
	free (prompt->model);
	free (prompt->provider);
	free (prompt);
}

static char *prompt_value_dup(const char *value) {
	char *res = strdup (value? value: "");
	r_str_trim (res);
	size_t len = strlen (res);
	if (len > 1 && ((res[0] == '\'' && res[len - 1] == '\'') || (res[0] == '"' && res[len - 1] == '"'))) {
		char *unquoted = r_str_ndup (res + 1, len - 2);
		free (res);
		res = unquoted;
	}
	return res;
}

static void prompt_set_value(char **dst, const char *value) {
	free (*dst);
	*dst = prompt_value_dup (value);
}

static bool prompt_set_key_value(R2AIPrompt *prompt, const char *raw_key, const char *raw_value) {
	char *key = strdup (raw_key);
	r_str_trim (key);
	r_str_case (key, false);
	char *p = key;
	for (; *p; p++) {
		if (*p == '-') {
			*p = '_';
		}
	}

	bool known = true;
	if (!strcmp (key, "title")) {
		prompt_set_value (&prompt->title, raw_value);
	} else if (!strcmp (key, "author")) {
		prompt_set_value (&prompt->author, raw_value);
	} else if (!strcmp (key, "description") || !strcmp (key, "desc")) {
		prompt_set_value (&prompt->desc, raw_value);
	} else if (!strcmp (key, "command") || !strcmp (key, "commands")) {
		prompt_set_value (&prompt->command, raw_value);
	} else if (!strcmp (key, "prompt") || !strcmp (key, "query")) {
		prompt_set_value (&prompt->prompt, raw_value);
	} else if (!strcmp (key, "requires")) {
		prompt_set_value (&prompt->requires, raw_value);
	} else if (!strcmp (key, "if_empty")) {
		prompt_set_value (&prompt->if_empty, raw_value);
	} else if (!strcmp (key, "if_command")) {
		prompt_set_value (&prompt->if_command, raw_value);
	} else if (!strcmp (key, "model")) {
		prompt_set_value (&prompt->model, raw_value);
	} else if (!strcmp (key, "provider")) {
		prompt_set_value (&prompt->provider, raw_value);
	} else {
		known = false;
	}
	free (key);
	return known;
}

static bool parse_prompt_kv(R2AIPrompt *prompt, const char *text) {
	bool parsed = false;
	char *data = strdup (text);
	RList *lines = r_str_split_list (data, "\n", -1);
	RListIter *iter;
	char *line;
	r_list_foreach (lines, iter, line) {
		r_str_trim (line);
		if (!*line || *line == '#') {
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
		if (prompt_set_key_value (prompt, key, value)) {
			parsed = true;
		}
	}
	r_list_free (lines);
	free (data);
	return parsed;
}

R_API R2AIPrompt *parse_prompt_file(const char *filepath) {
	R2AIPrompt *prompt = R_NEW0 (R2AIPrompt);
	char *content = r_file_slurp (filepath, NULL);
	if (!content) {
		free (prompt);
		return NULL;
	}

	if (r_str_startswith (content, "---\n")) {
		char *frontmatter_end = strstr (content + 4, "\n---\n");
		if (frontmatter_end) {
			char *frontmatter = r_str_ndup (content + 4, frontmatter_end - (content + 4));
			parse_prompt_kv (prompt, frontmatter);
			free (frontmatter);
			char *prompt_start = frontmatter_end + 5; // Skip "\n---\n"
			prompt->prompt = strdup (prompt_start);
		} else {
			R_LOG_ERROR ("Invalid prompt file format: %s", filepath);
			r2aiprompt_free (prompt);
			prompt = NULL;
		}
	} else if (!parse_prompt_kv (prompt, content)) {
		R_LOG_ERROR ("Invalid prompt file format: %s", filepath);
		r2aiprompt_free (prompt);
		prompt = NULL;
	} else if (!prompt->prompt && prompt->desc) {
		prompt->prompt = strdup (prompt->desc);
	}

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

// Helper function to find prompt file in search directories
R_API char *find_prompt_file(RList *search_dirs, const char *name) {
	char *filepath = NULL;
	RListIter *dir_iter;
	char *dir;
	r_list_foreach (search_dirs, dir_iter, dir) {
		char *filepath_md = r_str_newf ("%s/%s.r2ai.md", dir, name);
		char *filepath_txt = r_str_newf ("%s/%s.r2ai.txt", dir, name);
		if (r_file_exists (filepath_md)) {
			filepath = filepath_md;
			free (filepath_txt);
			break;
		} else if (r_file_exists (filepath_txt)) {
			filepath = filepath_txt;
			free (filepath_md);
			break;
		}
		free (filepath_md);
		free (filepath_txt);
	}
	return filepath;
}

static bool prompt_name_seen(RList *seen, const char *name) {
	RListIter *iter;
	char *it;
	r_list_foreach (seen, iter, it) {
		if (!strcmp (it, name)) {
			return true;
		}
	}
	return false;
}

static RList *prompt_search_dirs(RCore *core) {
	const char *promptdir = r_config_get (core->config, "r2ai.promptdir");
	if (!promptdir || !*promptdir) {
		promptdir = "~/.config/r2ai/prompts";
	}
	char *expanded_dir = r_file_abspath (promptdir);
	char *local_prompts = r_file_abspath ("../prompts");
	RList *search_dirs = r_list_newf (free);
	if (r_file_is_directory (expanded_dir)) {
		r_list_append (search_dirs, expanded_dir);
	} else {
		free (expanded_dir);
	}
	if (r_file_is_directory (local_prompts)) {
		r_list_append (search_dirs, local_prompts);
	} else {
		free (local_prompts);
	}
	return search_dirs;
}

static RList *prompt_search_dirs_or_warn(RCore *core) {
	RList *search_dirs = prompt_search_dirs (core);
	if (!r_list_empty (search_dirs)) {
		return search_dirs;
	}
	R_LOG_ERROR ("No prompt directories found");
	r_list_free (search_dirs);
	return NULL;
}

static void prompt_print_summary(RCore *core, const char *name, R2AIPrompt *prompt) {
	const char *title = r_str_get (prompt->title);
	const char *desc = r_str_get (prompt->desc);
	if (*title && *desc) {
		r_cons_printf (core->cons, "%s: %s - %s\n", name, title, desc);
	} else if (*title) {
		r_cons_printf (core->cons, "%s: %s\n", name, title);
	} else if (*desc) {
		r_cons_printf (core->cons, "%s: %s\n", name, desc);
	} else {
		r_cons_println (core->cons, name);
	}
}

static char *prompt_name_from_file(const char *file) {
	const char *suffix = r_str_endswith (file, ".r2ai.md")? ".r2ai.md": ".r2ai.txt";
	return r_str_ndup (file, strlen (file) - strlen (suffix));
}

static void prompt_json_ks(PJ *pj, const char *key, const char *value) {
	pj_ks (pj, key, r_str_get (value));
}

static void prompt_print_json(PJ *pj, const char *name, const char *filepath, R2AIPrompt *prompt) {
	pj_o (pj);
	pj_ks (pj, "name", name);
	pj_ks (pj, "path", filepath);
	pj_ks (pj, "format", r_str_endswith (filepath, ".r2ai.md")? "markdown": "legacy");
	pj_kb (pj, "valid", prompt != NULL);
	prompt_json_ks (pj, "title", prompt? prompt->title: NULL);
	prompt_json_ks (pj, "description", prompt? prompt->desc: NULL);
	prompt_json_ks (pj, "author", prompt? prompt->author: NULL);
	prompt_json_ks (pj, "command", prompt? prompt->command: NULL);
	prompt_json_ks (pj, "prompt", prompt? prompt->prompt: NULL);
	prompt_json_ks (pj, "requires", prompt? prompt->requires: NULL);
	prompt_json_ks (pj, "if_empty", prompt? prompt->if_empty: NULL);
	prompt_json_ks (pj, "if_command", prompt? prompt->if_command: NULL);
	prompt_json_ks (pj, "model", prompt? prompt->model: NULL);
	prompt_json_ks (pj, "provider", prompt? prompt->provider: NULL);
	pj_end (pj);
}

static void prompt_list(RCore *core, RList *search_dirs, bool json) {
	RList *seen = r_list_newf (free);
	PJ *pj = NULL;
	if (json) {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}
	RListIter *dir_iter;
	char *dir;
	r_list_foreach (search_dirs, dir_iter, dir) {
		RList *files = r_sys_dir (dir);
		RListIter *iter;
		char *file;
		r_list_foreach (files, iter, file) {
			if (!r_str_endswith (file, ".r2ai.txt") && !r_str_endswith (file, ".r2ai.md")) {
				continue;
			}
			char *name = prompt_name_from_file (file);
			if (prompt_name_seen (seen, name)) {
				free (name);
				continue;
			}
			r_list_append (seen, strdup (name));
			char *filepath = find_prompt_file (search_dirs, name);
			if (!filepath) {
				free (name);
				continue;
			}
			R2AIPrompt *prompt = parse_prompt_file (filepath);
			if (json) {
				prompt_print_json (pj, name, filepath, prompt);
			} else if (prompt) {
				prompt_print_summary (core, name, prompt);
			} else {
				r_cons_println (core->cons, name);
			}
			r2aiprompt_free (prompt);
			free (filepath);
			free (name);
		}
		r_list_free (files);
	}
	if (json) {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_println (core->cons, s);
		free (s);
	}
	r_list_free (seen);
}

R_API void r2ai_cmd_qj(RCorePluginSession *cps, const char *input) {
	(void)input;
	RCore *core = cps->core;
	RList *search_dirs = prompt_search_dirs_or_warn (core);
	if (!search_dirs) {
		return;
	}
	prompt_list (core, search_dirs, true);
	r_list_free (search_dirs);
}

R_API void r2ai_cmd_q(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	RList *search_dirs = prompt_search_dirs_or_warn (core);
	if (!search_dirs) {
		return;
	}
	if (!input || !*input) {
		prompt_list (core, search_dirs, false);
	} else {
		// run prompt
		char *name = strdup (input);
		char *extra = strchr (name, ' ');
		if (extra) {
			*extra++ = 0;
			r_str_trim (extra);
		}
		r_str_trim (name);
		char *filepath = find_prompt_file (search_dirs, name);
		if (!filepath) {
			R_LOG_ERROR ("Cannot find prompt file: %s.r2ai.txt or %s.r2ai.md", name, name);
			r_list_free (search_dirs);
			free (name);
			return;
		}
		R2AIPrompt *prompt = parse_prompt_file (filepath);
		if (!prompt) {
			R_LOG_ERROR ("Cannot read prompt file: %s", filepath);
			free (filepath);
			r_list_free (search_dirs);
			free (name);
			return;
		}
		if (!prompt->command) {
			R_LOG_WARN ("Prompt %s is missing required Command directive", name);
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
			if (!strcmp (prompt->if_empty, "exit")) {
				R_LOG_ERROR ("Command output is empty, exiting prompt");
				r2aiprompt_free (prompt);
				free (cmd_output);
				free (name);
				r_list_free (search_dirs);
				return;
			} else {
				use_prompt = prompt->if_empty;
			}
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
		char *res = r2ai (cps, (R2AIArgs){ .input = final_prompt, .model = prompt->model, .provider = prompt->provider, .error = &error, .dorag = true });
		if (error) {
			R_LOG_ERROR ("%s", error);
			free (error);
		} else if (res) {
			r_cons_printf (core->cons, "%s\n", res);
			free (res);
		}
		r2aiprompt_free (prompt);
		free (final_prompt);
		free (name);
	}
	r_list_free (search_dirs);
}

R_API char *r2ai_load_prompt_text(RCore *core, const char *name) {
	RList *search_dirs = prompt_search_dirs (core);
	char *filepath = find_prompt_file (search_dirs, name);
	char *prompt_text = NULL;
	if (filepath) {
		R2AIPrompt *prompt = parse_prompt_file (filepath);
		if (prompt && prompt->prompt) {
			prompt_text = strdup (prompt->prompt);
		}
		r2aiprompt_free (prompt);
		free (filepath);
	}

	r_list_free (search_dirs);
	return prompt_text;
}
