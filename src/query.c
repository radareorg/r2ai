/* r2ai - Copyright 2023-2025 pancake */

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

static R2AIPrompt *parse_prompt_file(const char *filepath) {
	R2AIPrompt *prompt = R_NEW0 (R2AIPrompt);
	char *content = r_file_slurp (filepath, NULL);
	if (!content) {
		free (prompt);
		return NULL;
	}

	// Check if it's a markdown file with YAML frontmatter
	if (r_str_startswith (content, "---\n")) {
		// Parse YAML frontmatter
		char *frontmatter_end = strstr (content + 4, "\n---\n");
		if (frontmatter_end) {
			char *frontmatter = r_str_ndup (content + 4, frontmatter_end - (content + 4));
			RList *lines = r_str_split_list (frontmatter, "\n", -1);
			RListIter *iter;
			char *line;
			r_list_foreach (lines, iter, line) {
				r_str_trim (line);
				if (*line == 0) {
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
				if (!strcmp (key, "title")) {
					prompt->desc = strdup (value);
				} else if (!strcmp (key, "author")) {
					prompt->author = strdup (value);
				} else if (!strcmp (key, "description")) {
					prompt->title = strdup (value);
				} else if (!strcmp (key, "command")) {
					prompt->command = strdup (value);
				} else if (!strcmp (key, "model")) {
					prompt->model = strdup (value);
				} else if (!strcmp (key, "provider")) {
					prompt->provider = strdup (value);
				}
			}
			r_list_free (lines);
			free (frontmatter);
			// The prompt content starts after the second ---
			char *prompt_start = frontmatter_end + 5; // Skip "\n---\n"
			prompt->prompt = strdup (prompt_start);
		}
	} else {
		R_LOG_ERROR ("Invalid prompt file format: %s", filepath);
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

R_API void r2ai_cmd_q(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
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
		expanded_dir = NULL;
	}
	if (r_file_is_directory (local_prompts)) {
		r_list_append (search_dirs, local_prompts);
	} else {
		free (local_prompts);
		local_prompts = NULL;
	}
	if (r_list_empty (search_dirs)) {
		R_LOG_ERROR ("No prompt directories found");
		r_list_free (search_dirs);
		return;
	}
	if (!input || !*input) {
		// list prompts
		RListIter *dir_iter;
		char *dir;
		r_list_foreach (search_dirs, dir_iter, dir) {
			RList *files = r_sys_dir (dir);
			RListIter *iter;
			char *file;
			r_list_foreach (files, iter, file) {
				if (r_str_endswith (file, ".r2ai.txt") || r_str_endswith (file, ".r2ai.md")) {
					char *dot = strchr (file, '.');
					char *name = dot? r_str_ndup (file, dot - file): strdup (file);
					char *filepath_txt = r_str_newf ("%s/%s.r2ai.txt", dir, name);
					char *filepath_md = r_str_newf ("%s/%s.r2ai.md", dir, name);
					char *filepath = NULL;
					if (r_file_exists (filepath_txt)) {
						filepath = filepath_txt;
					} else if (r_file_exists (filepath_md)) {
						filepath = filepath_md;
					}
					if (filepath) {
						R2AIPrompt *prompt = parse_prompt_file (filepath);
						if (prompt) {
							r_cons_printf (core->cons, "%s: %s - %s\n", name, prompt->title? prompt->title: "", prompt->desc? prompt->desc: "");
							r2aiprompt_free (prompt);
						} else {
							r_cons_println (core->cons, name);
						}
					}
					free (name);
					free (filepath_txt);
					free (filepath_md);
				}
			}
			r_list_free (files);
		}
	} else {
		// run prompt
		char *name = strdup (input);
		char *extra = strchr (name, ' ');
		if (extra) {
			*extra++ = 0;
			r_str_trim (extra);
		}
		r_str_trim (name);
		char *filepath = NULL;
		RListIter *dir_iter;
		char *dir;
		r_list_foreach (search_dirs, dir_iter, dir) {
			char *filepath_txt = r_str_newf ("%s/%s.r2ai.txt", dir, name);
			char *filepath_md = r_str_newf ("%s/%s.r2ai.md", dir, name);
			if (r_file_exists (filepath_txt)) {
				filepath = filepath_txt;
				free (filepath_md);
				break;
			} else if (r_file_exists (filepath_md)) {
				filepath = filepath_md;
				free (filepath_txt);
				break;
			}
			free (filepath_txt);
			free (filepath_md);
		}
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
