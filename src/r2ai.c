/* radare - Copyright 2023-2024 pancake */

#define R_LOG_ORIGIN "r2ai"

#include "r2ai.h"

static RCoreHelpMessage help_msg_r2ai = {
	"Usage:", "r2ai", "Use POST http://localhost:8000",
	"r2ai", " -m", "show selected model, list suggested ones, choose one",
	"r2ai", " -e", "Same as '-e r2ai.'",
	"r2ai", " -h", "Show this help message",
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
	char *provider = strdup (model);
	char *colon = strchr (provider, ':');
	if (colon) {
		*colon = 0;
		free (model);
		model = strdup (colon + 1);
	} else {
		free (provider);
		provider = strdup (r_config_get (core->config, "r2ai.api"));
	}
	R_LOG_DEBUG ("Model: %s", model);
	R_LOG_DEBUG ("Provider: %s", provider);
	bool stream = r_config_get_b (core->config, "r2ai.stream");
	char *result = NULL;
	if (R_STR_ISEMPTY (model)) {
		R_FREE (model);
	}
	if (!strcmp (provider, "openai")) {
		result = stream
			? r2ai_openai_stream (content, model, error)
			: r2ai_openai (content, model, error);
	} else if (!strcmp (provider, "openapi")) {
		result = r2ai_openapi (content, error);
	} else if (!strcmp (provider, "anthropic") || !strcmp (provider, "claude")) {
		result = stream
			? r2ai_anthropic_stream (content, model, error)
			: r2ai_anthropic (content, model, error);
	} else if (!strcmp (provider, "gemini")) {
		result = stream
			? r2ai_gemini_stream (content, model, error)
			: r2ai_gemini (content, model, error);
	} else {
		*error = strdup ("Unsupported provider. Use openai, openapi, anthropic");
	}
	
	free (provider);
	return result;
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
	} else if (r_str_startswith (input, "-m")) {
		cmd_r2ai_m (core, r_str_trim_head_ro (input + 2));
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
	r_config_set (core->config, "r2ai.api", "openapi");
	r_config_set (core->config, "r2ai.model", ""); // qwen2.5-4km");
	r_config_set (core->config, "r2ai.prompt", "");
	r_config_set_b (core->config, "r2ai.stream", true);
	r_config_lock (core->config, true);
	return true;
}

static int r2ai_fini(void *user, const char *input) {
	RCmd *cmd = (RCmd*)user;
	RCore *core = cmd->data;
	r_config_lock (core->config, false);
	r_config_rm (core->config, "r2ai.api");
	r_config_rm (core->config, "r2ai.model");
	r_config_rm (core->config, "r2ai.prompt");
	r_config_rm (core->config, "r2ai.stream");
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
		.name = "r2ai-client",
		.desc = "remote r2ai client using http post",
		.author = "pancake",
		.version = "0.9.2",
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
