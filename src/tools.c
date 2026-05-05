/* Copyright r2ai - 2023-2026 - pancake */

#include "r2ai.h"

R_API char *strip_command_comment(const char *input, char **comment_out) {
	const char *hash_pos = strchr (input, '#');
	char *stripped;
	if (hash_pos && (hash_pos == input || *(hash_pos - 1) != '\\')) {
		size_t cmd_len = hash_pos - input;
		stripped = r_str_ndup (input, cmd_len);
		r_str_trim (stripped);
		if (comment_out) {
			char *comment = strdup (hash_pos + 1); // skip #
			if (comment) {
				r_str_trim (comment);
				if (!*comment) {
					free (comment);
					comment = NULL;
				}
			}
			*comment_out = comment;
		}
	} else {
		stripped = strdup (input);
		if (comment_out) {
			*comment_out = NULL;
		}
	}
	return stripped;
}

// Define the radare2 command tool
static R2AI_Tool r2cmd_tool = {
	.name = "r2cmd",
	.description = "Run a radare2 command",
	.parameters = "{"
		"\"type\": \"object\","
		"\"properties\": {"
		"\"command\": {"
		"\"type\": \"string\","
		"\"description\": \"The radare2 command to run\""
		"}"
		"},"
		"\"required\": [\"command\"]"
		"}"
};

static R2AI_Tool qjs_tool = {
	.name = "execute_js",
	.description = "Execute a JavaScript script inside the radare2 environment. Use `var RESULT=r2.cmd(COMMAND)` to execute radare2 commands and `r2.log(MESSAGE)` instead of console.log`",
	.parameters = "{"
		"\"type\": \"object\","
		"\"properties\": {"
		"\"script\": {"
		"\"type\": \"string\","
		"\"description\": \"The JavaScript script to execute\""
		"}"
		"},"
		"\"required\": [\"script\"]"
		"}"
};

// Function to get the tools instance from state
R_API RList *r2ai_get_tools(RCore *core, R2AI_State *state) {
	if (!state) {
		return NULL;
	}
	if (!state->tools) {
		state->tools = r_list_newf (NULL);
	}
	if (!state->tools) {
		return NULL;
	}
	r_list_purge (state->tools);
	r_list_append (state->tools, (void *)&r2cmd_tool);
	// Reflect the current config instead of caching the first-seen value.
	if (r_config_get_b (core->config, "r2ai.auto.usejs")) {
		r_list_append (state->tools, (void *)&qjs_tool);
	}
	return state->tools;
}

// Function to parse input tools_json (OpenAI format) into R2AI_Tool list
R_API RList *r2ai_tools_parse(const char *tools_json) {
	if (!tools_json) {
		return NULL;
	}

	RJson *json = r_json_parse ((char *)tools_json);
	if (!json || json->type != R_JSON_ARRAY) {
		R_LOG_ERROR ("Invalid tools JSON format - expected array");
		r_json_free (json);
		return NULL;
	}

	RList *tools = r_list_new ();
	if (!tools) {
		r_json_free (json);
		return NULL;
	}
	tools->free = (RListFree)free; // Tools are dynamically allocated

	for (size_t i = 0; i < json->children.count; i++) {
		const RJson *tool_json = r_json_item (json, i);
		if (!tool_json || tool_json->type != R_JSON_OBJECT) {
			continue;
		}

		const RJson *type = r_json_get (tool_json, "type");
		if (!type || type->type != R_JSON_STRING || strcmp (type->str_value, "function") != 0) {
			continue;
		}

		const RJson *function = r_json_get (tool_json, "function");
		if (!function || function->type != R_JSON_OBJECT) {
			continue;
		}

		const RJson *name = r_json_get (function, "name");
		const RJson *description = r_json_get (function, "description");
		const RJson *parameters = r_json_get (function, "parameters");

		if (!name || name->type != R_JSON_STRING) {
			continue;
		}

		R2AI_Tool *tool = R_NEW0 (R2AI_Tool);
		tool->name = strdup (name->str_value);

		if (description && description->type == R_JSON_STRING) {
			tool->description = strdup (description->str_value);
		}

		if (parameters) {
			// Convert parameters to JSON string
			char *params_str = r_json_to_string (parameters);
			if (params_str) {
				tool->parameters = params_str; // r_json_to_string returns allocated string
			} else {
				tool->parameters = strdup ("{}");
			}
		}

		r_list_append (tools, tool);
	}

	r_json_free (json);
	return tools;
}

// Function to convert R2AI_Tools to OpenAI format JSON
R_API char *r2ai_tools_to_openai_json(const RList *tools) {
	if (!tools || r_list_length (tools) <= 0) {
		return NULL;
	}

	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}

	pj_a (pj);

	RListIter *iter;
	R2AI_Tool *tool;
	int a = 0;
	r_list_foreach (tools, iter, tool) {
		if (a > 0) {
#if R2_VERSION_NUMBER < 60005
			// XXX this is a bug
//			pj_raw (pj, ",");
#endif
		}
		a++;
		if (!tool->name) {
			continue;
		}
		pj_o (pj); // Start tool object
		pj_ks (pj, "type", "function");
		pj_ko (pj, "function");
		pj_ks (pj, "name", tool->name);
		if (tool->description) {
			pj_ks (pj, "description", tool->description);
		}
		if (tool->parameters) {
			pj_k (pj, "parameters");
			pj_raw (pj, tool->parameters);
		}
		pj_end (pj); // End function object
		pj_end (pj); // End tool object
#if R2_VERSION_NUMBER < 60005
		break;
#endif
	}

	pj_end (pj);

	char *result = pj_drain (pj);
	// eprintf ("((((((((((((((((((\n\n%s\n\n)))))))))))))\n", result);
	R_LOG_DEBUG ("OpenAI tools JSON: %s", result);
	return result;
}

// Function to convert R2AI_Tools to Anthropic format JSON
R_API char *r2ai_tools_to_anthropic_json(const RList *tools) {
	if (!tools || r_list_length (tools) <= 0) {
		return NULL;
	}

	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}

	pj_a (pj); // Start array

	RListIter *iter;
	R2AI_Tool *tool;
	r_list_foreach (tools, iter, tool) {
		if (!tool->name) {
			continue;
		}
		pj_o (pj); // Start tool object
		pj_ks (pj, "name", tool->name);
		if (tool->description) {
			pj_ks (pj, "description", tool->description);
		}
		if (tool->parameters) {
			pj_k (pj, "input_schema");
			pj_raw (pj, tool->parameters);
		}
		pj_end (pj); // End tool object
	}

	pj_end (pj); // End array

	char *result = pj_drain (pj);
	return result;
}

// Function to free a tools structure
R_API void r2ai_tools_free(RList *tools) {
	if (!tools) {
		return;
	}

	r_list_free (tools);
}

static char *to_cmd(const char *command) {
	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}

	pj_o (pj);
	pj_ks (pj, "cmd", command);
	pj_end (pj);

	return pj_drain (pj);
}

static char *compose_command_with_comment(const char *command, const char *comment) {
	if (!command) {
		return NULL;
	}
	if (!comment || !*comment) {
		return strdup (command);
	}
	return r_str_newf ("%s # %s", command, comment);
}

R_API void r2ai_tool_result_fini(R2AI_ToolResult *result) {
	if (!result) {
		return;
	}
	free (result->output);
	free (result->edited_command);
	free (result->comment);
	memset (result, 0, sizeof (*result));
}

static R2AI_ToolResult r2ai_r2cmd(RCore *core, RJson *args, bool verbose) {
	R2AI_ToolResult result = { 0 };
	if (!args) {
		result.output = strdup ("{ \"res\":\"Command is NULL\" }");
		return result;
	}

	const RJson *command_json = r_json_get (args, "command");
	if (!command_json || !command_json->str_value) {
		result.output = strdup ("{ \"res\":\"No command in tool call arguments\" }");
		return result;
	}

	char *comment = NULL;
	char *command = strip_command_comment (command_json->str_value, &comment);
	if (!command) {
		free (comment);
		result.output = strdup ("{ \"res\":\"Command is NULL\" }");
		return result;
	}

	if (r_str_startswith (command, "r2 ")) {
		free (command);
		free (comment);
		result.output = strdup ("{ \"res\":\"You are already in r2!\" }");
		return result;
	}

	bool ask_to_execute = r_config_get_b (core->config, "r2ai.auto.yolo") != true;
	if (ask_to_execute) {
		char *input_command = compose_command_with_comment (command, comment);
		if (!input_command) {
			free (command);
			free (comment);
			result.output = strdup ("{ \"res\":\"Failed to prepare command\" }");
			return result;
		}
		bool is_multiline = strchr (input_command, '\n') != NULL;

		if (is_multiline) {
			r_cons_editor (core->cons, NULL, input_command);
		} else {
			r_cons_newline (core->cons);
			r_cons_readpush (core->cons, input_command, strlen (input_command));
			r_cons_readpush (core->cons, "\x05", 1);
			r_line_set_prompt (core->cons->line, "[r2ai]> ");
			const char *readline_result = r_line_readline (core->cons);
			if (r_cons_is_breaked (core->cons) || R_STR_ISEMPTY (readline_result)) {
				R_LOG_INFO ("Command execution cancelled %s", readline_result);
				free (input_command);
				free (command);
				free (comment);
				result.output = strdup ("R2AI_SIGINT");
				return result;
			}
			if (R_STR_ISNOTEMPTY (readline_result)) {
				free (input_command);
				input_command = strdup (readline_result);
			}
		}

		char *new_comment = NULL;
		char *new_command = strip_command_comment (input_command, &new_comment);
		if (new_command) {
			free (command);
			command = new_command;
			free (comment);
			comment = new_comment;
		} else {
			free (new_comment);
		}
		free (input_command);
	}

	result.edited_command = strdup (command);
	R_LOG_DEBUG ("Edited command: %s", command);

	if (verbose) {
		char *display_command = compose_command_with_comment (command, comment);
		if (display_command) {
			char *red_command = r_str_newf (Color_RED "%s" Color_RESET "\n", display_command);
			r_cons_printf (core->cons, "%s", red_command);
			r_cons_flush (core->cons);
			free (red_command);
			free (display_command);
		}
	}

	char *json_cmd = to_cmd (command);
	if (!json_cmd) {
		free (command);
		free (comment);
		r2ai_tool_result_fini (&result);
		result.output = strdup ("{ \"res\":\"Failed to create JSON command\" }");
		return result;
	}

	char *cmd_output = r2ai_cmdstr (core, json_cmd);
	free (json_cmd);
	free (command);

	if (!cmd_output) {
		free (comment);
		r2ai_tool_result_fini (&result);
		result.output = strdup ("{ \"res\":\"Command returned no output or failed\" }");
		return result;
	}

	result.output = cmd_output;
	result.comment = comment;
	return result;
}

/**
 * Execute r_core_cmd_str with slim mode if enabled
 * Temporarily sets slim r2 commands output
 */
R_API char *r2ai_cmdstr(RCore *core, const char *cmd) {
	if (!r_config_get_b (core->config, "r2ai.auto.slim")) {
		return r_core_cmd_str (core, cmd);
	}

	RConfigHold *hold = r_config_hold_new (core->config);
	r_config_hold (hold, "asm.lines", "asm.lines.fcn", "scr.utf8", "asm.bytes", "emu.str", NULL);
	r_config_set_b (core->config, "asm.lines", false);
	r_config_set_b (core->config, "asm.lines.fcn", false);
	r_config_set_b (core->config, "scr.utf8", false);
	r_config_set_b (core->config, "asm.bytes", false);
	r_config_set_b (core->config, "emu.str", true);

	char *result = r_core_cmd_str (core, cmd);

	r_config_hold_restore (hold);
	r_config_hold_free (hold);

	return result;
}

// qjs function implementation
static R2AI_ToolResult r2ai_qjs(RCore *core, R2AI_State *state, RJson *args, bool verbose) {
	R2AI_ToolResult result = { 0 };
	if (!args) {
		result.output = strdup ("{ \"res\":\"Script is NULL\" }");
		return result;
	}

	const RJson *script_json = r_json_get (args, "script");
	if (!script_json) {
		result.output = strdup ("{ \"res\":\"No script field found in arguments\" }");
		return result;
	}

	if (!script_json->str_value) {
		result.output = strdup ("{ \"res\":\"Script value is NULL or empty\" }");
		return result;
	}

	bool ask_to_execute = r_config_get_b (core->config, "r2ai.auto.yolo") != true;
	const char *script = script_json->str_value;
	char *edited_script = NULL;

	if (ask_to_execute) {
		// Check if script contains newlines to determine if it's multi-line
		bool is_multiline = strchr (script, '\n') != NULL;

		if (is_multiline) {
			// Use editor for multi-line scripts
			edited_script = strdup (script);
			r_cons_editor (core->cons, NULL, edited_script);
			script = edited_script;
		} else {
			// For single-line scripts, push the script to input buffer

			r_cons_readpush (core->cons, script, strlen (script));
			r_cons_readpush (core->cons, "\x05", 1); // Ctrl+E - move to end
			r_line_set_prompt (core->cons->line, "[r2ai]> ");
			const char *readline_result = r_line_readline (core->cons);

			// Check if interrupted or ESC pressed (readline_result is NULL or empty)
			if (r_cons_is_breaked (core->cons) || R_STR_ISEMPTY (readline_result)) {
				free (edited_script); // Free if already allocated
				result.output = strdup ("R2AI_SIGINT");
				return result;
			}

			// Process the result
			if (readline_result && *readline_result) {
				edited_script = strdup (readline_result);
				script = edited_script;
			} else {
				// If user just pressed enter, keep the original script
				edited_script = strdup (script);
				script = edited_script;
			}
		}
	}

	result.edited_command = strdup (script);

	if (verbose) {
		char *print_script = r_str_newf ("\n```js\n%s\n```", script);
		char *print_script_rendered = r2ai_markdown (state? &state->markdown: NULL, print_script);
		r_cons_printf (core->cons, "%s\n", print_script_rendered);
		r_cons_flush (core->cons);
		free (print_script);
		free (print_script_rendered);
	}
	char *payload = r_str_newf ("var console = { log:r2log, warn:r2log, info:r2log, error:r2log, debug:r2log };%s", script);

	// Free edited_script after we're done using it
	free (edited_script);

	if (!payload) {
		r2ai_tool_result_fini (&result);
		result.output = strdup ("{ \"res\":\"Failed to create script payload\" }");
		return result;
	}

	R_LOG_DEBUG ("Payload length: %d", (int)strlen (payload));

	char *payload_base64 = r_base64_encode_dyn ((const ut8 *)payload, strlen (payload));
	if (!payload_base64) {
		free (payload);
		r2ai_tool_result_fini (&result);
		result.output = strdup ("{ \"res\":\"Failed to encode script\" }");
		return result;
	}

	char *cmd = r_str_newf ("#!qjs -e base64:%s", payload_base64);
	R_LOG_DEBUG ("Command length: %d", (int)strlen (cmd));
	free (payload);
	free (payload_base64);

	char *json_cmd = to_cmd (cmd);
	if (!json_cmd) {
		free (cmd);
		r2ai_tool_result_fini (&result);
		result.output = strdup ("{ \"res\":\"Failed to execute qjs\" }");
		return result;
	}

	char *cmd_output = r_core_cmd_str (core, json_cmd);
	free (json_cmd);
	free (cmd);

	result.output = cmd_output;
	return result;
}

static char *tool_logs_to_string(const RJson *logs_json) {
	if (!logs_json || logs_json->type != R_JSON_ARRAY) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	for (size_t i = 0; i < logs_json->children.count; i++) {
		const RJson *log = r_json_item (logs_json, i);
		if (log && log->type == R_JSON_OBJECT) {
			const RJson *type = r_json_get (log, "type");
			const RJson *message = r_json_get (log, "message");
			if (message && message->type == R_JSON_STRING) {
				if (type && type->type == R_JSON_STRING && R_STR_ISNOTEMPTY (type->str_value)) {
					r_strbuf_appendf (sb, "%s: ", type->str_value);
				}
				r_strbuf_appendf (sb, "%s\n", message->str_value);
			}
		}
	}
	char *s = r_strbuf_drain (sb);
	if (R_STR_ISEMPTY (s)) {
		free (s);
		return NULL;
	}
	return s;
}

static void normalize_tool_output(RCore *core, bool verbose, const char *tool_name, const char *args, R2AI_ToolResult *result) {
	if (R_STR_ISEMPTY (result->output)) {
		free (result->output);
		result->output = strdup (!strcmp (tool_name, "execute_js")
			? "Error: Empty or invalid response from QJS execution"
			: "<no output>");
		return;
	}
	if (!strcmp (result->output, "R2AI_SIGINT")) {
		return;
	}
	if (!r_str_startswith (result->output, "{") || !strchr (result->output, '}')) {
		return;
	}

	RJson *json = r_json_parse (result->output);
	if (!json) {
		R_LOG_WARN ("Failed to parse JSON response from tool execution");
		return;
	}

	char *normalized = NULL;
	const RJson *logs_json = r_json_get (json, "logs");
	const RJson *error_json = r_json_get (json, "error");
	if (error_json && (error_json->type == R_JSON_BOOLEAN || error_json->type == R_JSON_STRING) &&
		((error_json->type == R_JSON_BOOLEAN && error_json->num.u_value) ||
			(error_json->type == R_JSON_STRING && error_json->str_value[0]))) {
		normalized = tool_logs_to_string (logs_json);
		if (!normalized && error_json->type == R_JSON_STRING) {
			normalized = strdup (error_json->str_value);
		}
		if (!normalized) {
			normalized = strdup ("Error occurred (no details available)");
		}
	} else {
		const RJson *res_json = r_json_get (json, "res");
		if (res_json && res_json->type == R_JSON_STRING) {
			normalized = strdup (res_json->str_value);
		} else {
			normalized = strdup (result->output);
		}
		if (R_STR_ISEMPTY (normalized)) {
			free (normalized);
			normalized = tool_logs_to_string (logs_json);
		}
		if (!normalized && !strcmp (tool_name, "r2cmd")) {
			normalized = strdup ("<no output>");
		}
		if (!normalized) {
			normalized = strdup ("<no output>");
		}
	}
	r_json_free (json);

	if (!normalized) {
		normalized = r_str_newf ("Error running tool: Unknown error\nCommand: %s", args);
	}
	free (result->output);
	result->output = normalized;

	if (verbose) {
		r_cons_newline (core->cons);
		r_cons_printf (core->cons, "%s\n", result->output);
		r_cons_newline (core->cons);
		r_cons_flush (core->cons);
	}
	r_str_ansi_strip (result->output);
}

R_API R2AI_ToolResult execute_tool(RCorePluginSession *cps, const char *tool_name, const char *args) {
	R2AI_ToolResult result = { 0 };
	if (!cps || !cps->core) {
		result.output = strdup ("{ \"res\":\"Missing r2ai session\" }");
		return result;
	}
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	if (!tool_name || !args) {
		result.output = strdup ("{ \"res\":\"Tool name or arguments are NULL\" }");
		return result;
	}

	R_LOG_DEBUG ("Args: %s", args);

	// Check if args is valid JSON before parsing
	if (!r_str_startswith (args, "{") || !strchr (args, '}')) {
		result.output = r_str_newf ("Invalid JSON arguments: %s", args);
		return result;
	}

	RJson *args_json = r_json_parse ((char *)args);
	if (!args_json) {
		result.output = r_str_newf ("Failed to parse arguments: %s", args);
		return result;
	}

	bool verbose = r_config_get_b (core->config, "r2ai.auto.verbose");

	if (strcmp (tool_name, "r2cmd") == 0) {
		result = r2ai_r2cmd (core, args_json, verbose);
	} else if (strcmp (tool_name, "execute_js") == 0) {
		result = r2ai_qjs (core, state, args_json, verbose);
	} else {
		result.output = strdup ("{ \"res\":\"Unknown tool\" }");
	}
	r_json_free (args_json);
	normalize_tool_output (core, verbose, tool_name, args, &result);
	return result;
}
