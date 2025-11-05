/* r2ai - Copyright 2023-2025 pancake */

#define R_LOG_ORIGIN "r2ai"

#include "r2ai.h"
#include "r2ai_priv.h"

/* Return the path to the apikeys.txt file */
R_IPI char *r2ai_apikeys_path(bool *exists) {
	char *path = r_file_home (".config/r2ai/apikeys.txt");
	if (exists) {
		*exists = r_file_exists (path);
	}
	return path;
}

/* Edit the API keys file */
R_IPI void r2ai_apikeys_edit(RCorePluginSession *cps) {
	RCore *core = cps->core;
	bool exists = false;
	char *keys_path = r2ai_apikeys_path (&exists);
	if (!exists) {
		const char *template = "# API Keys configuration for r2ai\n"
				"\n"
				"# Specify your API keys in the format: PROVIDER=KEY\n"
				"# OpenAI=sk-your-openai-api-key-here\n"
				"# MISTRAL=your-mistral-api-key-here\n";
		r_file_dump (keys_path, (const ut8 *)template, strlen (template), 0);
	}
	r_cons_editor (core->cons, keys_path, NULL);
	free (keys_path);
}

/* Return a malloc'd API key read from ~/.config/r2ai/apikeys.txt
 * Provider matching is case-insensitive */
R_IPI char *r2ai_apikeys_get(const char *provider) {
	if (!provider) {
		return NULL;
	}
	bool exists = false;
	char *config_file = r2ai_apikeys_path (&exists);
	if (!exists) {
		free (config_file);
		return NULL;
	}
	char *content = r_file_slurp (config_file, NULL);
	free (config_file);
	if (!content) {
		return NULL;
	}
	RList *lines = r_str_split_list (content, "\n", 0);
	char *key = NULL;
	if (lines) {
		RListIter *iter;
		char *line;
		r_list_foreach (lines, iter, line) {
			const char *trimmed = r_str_trim_head_ro (line);
			if (R_STR_ISEMPTY (trimmed) || *trimmed == '#') {
				continue;
			}
			char *eq = strchr (trimmed, '=');
			if (eq) {
				size_t provider_len = eq - trimmed;
				char *line_provider = r_str_ndup (trimmed, provider_len);
				if (r_str_casecmp (line_provider, provider) == 0) {
					key = strdup (eq + 1);
					r_str_trim (key);
					free (line_provider);
					break;
				}
				free (line_provider);
			}
		}
		r_list_free (lines);
	}
	free (content);
	return key;
}
