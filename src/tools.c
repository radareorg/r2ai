/* Copyright r2ai - 2023-2025 - pancake */

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
		r_list_append (state->tools, (void *)&r2cmd_tool);
		// Only add execute_js tool if enabled in config
		if (r_config_get_b (core->config, "r2ai.auto.usejs")) {
			r_list_append (state->tools, (void *)&qjs_tool);
		}
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

R_API char *r2ai_r2cmd(RCore *core, RJson *args, bool hide_tool_output, char **edited_command, char **comment_out) {
	if (!args) {
		return strdup ("{ \"res\":\"Command is NULL\" }");
	}

	const RJson *command_json = r_json_get (args, "command");
	if (!command_json || !command_json->str_value) {
		return strdup ("{ \"res\":\"No command in tool call arguments\" }");
	}

	if (edited_command) {
		*edited_command = NULL;
	}

	char *comment = NULL;
	char *command = strip_command_comment (command_json->str_value, &comment);
	if (!command) {
		free (comment);
		return strdup ("{ \"res\":\"Command is NULL\" }");
	}

	if (r_str_startswith (command, "r2 ")) {
		free (command);
		free (comment);
		if (comment_out) {
			*comment_out = NULL;
		}
		return strdup ("{ \"res\":\"You are already in r2!\" }");
	}

	bool ask_to_execute = r_config_get_b (core->config, "r2ai.auto.yolo") != true;
	if (ask_to_execute) {
		bool is_multiline = strchr (command, '\n') != NULL;
		char *input_command = compose_command_with_comment (command, comment);
		if (!input_command) {
			free (command);
			free (comment);
			return strdup ("{ \"res\":\"Failed to prepare command\" }");
		}

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
				if (comment_out) {
					*comment_out = NULL;
				}
				return strdup ("R2AI_SIGINT");
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

	if (edited_command) {
		*edited_command = strdup (command);
	}
	R_LOG_DEBUG ("Edited command: %s", command);

	if (!hide_tool_output) {
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
		if (comment_out) {
			*comment_out = NULL;
		}
		return strdup ("{ \"res\":\"Failed to create JSON command\" }");
	}

	char *cmd_output = r_core_cmd_str (core, json_cmd);
	free (json_cmd);
	free (command);

	if (!cmd_output) {
		free (comment);
		if (comment_out) {
			*comment_out = NULL;
		}
		return strdup ("{ \"res\":\"Command returned no output or failed\" }");
	}

	if (comment_out) {
		*comment_out = comment;
	} else {
		free (comment);
	}

	return cmd_output;
}

// qjs function implementation
R_API char *r2ai_qjs(RCore *core, RJson *args, bool hide_tool_output, char **edited_script_out) {
	if (!args) {
		return strdup ("{ \"res\":\"Script is NULL\" }");
	}

	if (edited_script_out) {
		*edited_script_out = NULL;
	}

	const RJson *script_json = r_json_get (args, "script");
	if (!script_json) {
		return strdup ("{ \"res\":\"No script field found in arguments\" }");
	}

	if (!script_json->str_value) {
		return strdup ("{ \"res\":\"Script value is NULL or empty\" }");
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
				return strdup ("R2AI_SIGINT");
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

	if (edited_script_out) {
		char *dup_script = strdup (script);
		if (dup_script) {
			*edited_script_out = dup_script;
		}
	}

	if (!hide_tool_output) {
		char *print_script = r_str_newf ("\n```js\n%s\n```", script);
		char *print_script_rendered = r2ai_markdown (print_script);
		r_cons_printf (core->cons, "%s\n", print_script_rendered);
		r_cons_flush (core->cons);
		free (print_script);
		free (print_script_rendered);
	}
	char *payload = r_str_newf ("var console = { log:r2log, warn:r2log, info:r2log, error:r2log, debug:r2log };%s", script);

	// Free edited_script after we're done using it
	free (edited_script);

	R_LOG_DEBUG ("Payload length: %d", (int)strlen (payload));

	if (!payload) {
		return strdup ("{ \"res\":\"Failed to create script payload\" }");
	}

	char *payload_base64 = r_base64_encode_dyn ((const ut8 *)payload, strlen (payload));
	if (!payload_base64) {
		free (payload);
		return strdup ("{ \"res\":\"Failed to encode script\" }");
	}

	char *cmd = r_str_newf ("#!qjs -e base64:%s", payload_base64);
	R_LOG_DEBUG ("Command length: %d", (int)strlen (cmd));
	free (payload);
	free (payload_base64);

	char *json_cmd = to_cmd (cmd);
	if (!json_cmd) {
		free (cmd);
		return strdup ("{ \"res\":\"Failed to execute qjs\" }");
	}

	char *cmd_output = r_core_cmd_str (core, json_cmd);
	free (json_cmd);
	free (cmd);

	return cmd_output;
}

R_API char *execute_tool(RCore *core, const char *tool_name, const char *args, char **edited_command, char **comment_out) {
	if (!tool_name || !args) {
		return strdup ("{ \"res\":\"Tool name or arguments are NULL\" }");
	}

	R_LOG_DEBUG ("Args: %s", args);

	// Check if args is valid JSON before parsing
	if (!r_str_startswith (args, "{") || !strchr (args, '}')) {
		return r_str_newf ("Invalid JSON arguments: %s", args);
	}

	RJson *args_json = r_json_parse ((char *)args);
	if (!args_json) {
		return r_str_newf ("Failed to parse arguments: %s", args);
	}

	bool hide_tool_output = r_config_get_b (core->config, "r2ai.auto.hide_tool_output");
	char *tool_result = NULL;

	if (strcmp (tool_name, "r2cmd") == 0) {
		tool_result = r2ai_r2cmd (core, args_json, hide_tool_output, edited_command, comment_out);
	} else {
		if (comment_out) {
			*comment_out = NULL;
		}
		if (strcmp (tool_name, "execute_js") == 0) {
			tool_result = r2ai_qjs (core, args_json, hide_tool_output, edited_command);
		} else {
			tool_result = strdup ("{ \"res\":\"Unknown tool\" }");
		}
	}

	// Check for interruption after executing the tool
	if (tool_result && strcmp (tool_result, "R2AI_SIGINT") == 0) {
		free (tool_result);
		return strdup ("R2AI_SIGINT");
	}

	// Try to parse as JSON (equivalent to json.loads in Python)
	char *result = NULL;

	// Check for empty or invalid response that could cause a crash
	if (R_STR_ISEMPTY (tool_result)) {
		free (tool_result);
		return strdup ("{ \"res\":\"Error: Empty or invalid response from QJS execution\" }");
	}

	// Validate that the tool_result looks like valid JSON before parsing
	if (!r_str_startswith (tool_result, "{") || !strchr (tool_result, '}')) {
		// Not a JSON object, return as plain text
		return tool_result;
	}

	// Try to parse the JSON safely
	RJson *json = r_json_parse (tool_result);

	if (!json) {
		// JSON parsing failed, return original content
		R_LOG_WARN ("Failed to parse JSON response from tool execution");
		return tool_result;
	}

	if (json) {
		// Check for error field
		const RJson *error_json = r_json_get (json, "error");
		if (error_json && (error_json->type == R_JSON_BOOLEAN || error_json->type == R_JSON_STRING) &&
			((error_json->type == R_JSON_BOOLEAN && error_json->num.u_value) ||
				(error_json->type == R_JSON_STRING && error_json->str_value[0]))) {

			// Build error message from logs if available
			const RJson *logs_json = r_json_get (json, "logs");
			if (logs_json && logs_json->type == R_JSON_ARRAY) {
				RStrBuf *sb = r_strbuf_new ("");

				for (size_t i = 0; i < logs_json->children.count; i++) {
					const RJson *log = r_json_item (logs_json, i);
					if (log && log->type == R_JSON_OBJECT) {
						const RJson *message = r_json_get (log, "message");
						if (message && message->type == R_JSON_STRING) {
							r_strbuf_appendf (sb, "%s\n", message->str_value);
						}
					}
				}

				result = r_strbuf_drain (sb);
			} else {
				// If no logs, return the error message directly
				if (error_json->type == R_JSON_STRING) {
					result = strdup (error_json->str_value);
				} else {
					result = strdup ("Error occurred (no details available)");
				}
			}
		} else {
			// Extract res field
			const RJson *res_json = r_json_get (json, "res");
			if (res_json && res_json->type == R_JSON_STRING) {
				result = strdup (res_json->str_value);
			} else {
				// Just return the entire command output if res field not found
				result = strdup (tool_result);
			}
		}

		r_json_free (json);
	} else {
		// JSON parse failed, handle like JSONDecodeError in Python
		char *trimmed = r_str_trim_dup (tool_result);
		if (trimmed) {
			// Manual line splitting to avoid r_str_split issues
			RList *lines = r_str_split_list (trimmed, "\n", 0);
			if (lines) {
				int line_count = r_list_length (lines);
				if (line_count > 0) {
					char *last_line = r_list_get_n (lines, line_count - 1);
					if (last_line && r_str_startswith (last_line, "{\"res\":\"\"")) {
						// Remove the last line by joining all lines except the last
						RStrBuf *sb = r_strbuf_new ("");
						int i = 0;

						// Use manual iteration instead of r_list_foreach_n
						RListIter *iter;
						char *line;
						r_list_foreach (lines, iter, line) {
							// Skip the last line
							if (line != last_line) {
								if (i > 0) {
									r_strbuf_append (sb, "\n");
								}
								r_strbuf_append (sb, line);
								i++;
							}
						}

						result = r_strbuf_drain (sb);
					} else {
						// Keep the output as is
						result = strdup (tool_result);
					}
				} else {
					result = strdup (tool_result);
				}
				r_list_free (lines);
			} else {
				result = strdup (tool_result);
			}
			free (trimmed);
		} else {
			result = strdup (tool_result);
		}
	}

	free (tool_result);

	if (!result) {
		return r_str_newf ("Error running tool: Unknown error\nCommand: %s", args);
	}
	if (!hide_tool_output) {
		r_cons_newline (core->cons);
		r_cons_printf (core->cons, "%s\n", result);
		r_cons_newline (core->cons);
		r_cons_flush (core->cons);
	}

	r_str_ansi_strip (result);

	r_json_free (args_json);
	return result;
}
