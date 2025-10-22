#include <string.h>
#include "r2ai.h"

// Define the radare2 command tool
static R2AI_Tool r2cmd_tool = {
	.name = "r2cmd",
	.description = "Run a radare2 command",
	.parameters = "{\
		\"type\": \"object\",\
		\"properties\": {\
			\"command\": {\
				\"type\": \"string\",\
				\"description\": \"The radare2 command to run\"\
			}\
		},\
		\"required\": [\"command\"]\
	}"
};

static R2AI_Tool qjs_tool = {
	.name = "execute_js",
	.description = "Execute a JavaScript script inside the radare2 environment. Use `var RESULT=r2.cmd(COMMAND)` to execute radare2 commands and `r2.log(MESSAGE)` instead of console.log`",
	.parameters = "{\
		\"type\": \"object\",\
		\"properties\": {\
			\"script\": {\
				\"type\": \"string\",\
				\"description\": \"The JavaScript script to execute\"\
			}\
		},\
		\"required\": [\"script\"]\
	}"
};

// Create a global tools structure with our tools
static R2AI_Tools r2ai_tools_instance = {
	.tools = NULL, // Will initialize below
	.n_tools = 2
};

// Function to get the global tools instance
R_API const R2AI_Tools *r2ai_get_tools(void) {
	// Initialize tools array if not done yet
	if (!r2ai_tools_instance.tools) {
		static R2AI_Tool tools_array[2];
		tools_array[0] = r2cmd_tool;
		tools_array[1] = qjs_tool;
		r2ai_tools_instance.tools = tools_array;
	}
	return &r2ai_tools_instance;
}

// Function to parse input tools_json (OpenAI format) into R2AI_Tool array
R_API R2AI_Tools *r2ai_tools_parse(const char *tools_json) {
	if (!tools_json) {
		return NULL;
	}

	RJson *json = r_json_parse ((char *)tools_json);
	if (!json || json->type != R_JSON_ARRAY) {
		R_LOG_ERROR ("Invalid tools JSON format - expected array");
		r_json_free (json);
		return NULL;
	}

	R2AI_Tools *tools = R_NEW0 (R2AI_Tools);

	int n_tools = json->children.count;
	tools->tools = R_NEWS0 (R2AI_Tool, n_tools);
	if (!tools->tools) {
		free (tools);
		r_json_free (json);
		return NULL;
	}
	tools->n_tools = n_tools;

	int valid_tools = 0;
	for (int i = 0; i < n_tools; i++) {
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

		R2AI_Tool *tool = &tools->tools[valid_tools++];
		tool->name = strdup (name->str_value);

		if (description && description->type == R_JSON_STRING) {
			tool->description = strdup (description->str_value);
		}

		if (parameters) {
			// Just pass through the JSON as a string
			if (parameters->type == R_JSON_STRING) {
				tool->parameters = strdup (parameters->str_value);
			} else {
				// Use pj_raw to pass through any other raw JSON
				PJ *pj = pj_new ();
				if (pj) {
					pj_raw (pj, "{}");
					char *params_str = pj_drain (pj);
					if (params_str) {
						tool->parameters = strdup (params_str);
						free (params_str);
					}
				}
			}
		}
	}

	// Update count of valid tools
	tools->n_tools = valid_tools;

	r_json_free (json);
	return tools;
}

// Function to convert R2AI_Tools to OpenAI format JSON
R_API char *r2ai_tools_to_openai_json(const R2AI_Tools *tools) {
	if (!tools || tools->n_tools <= 0) {
		return NULL;
	}

	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}

	pj_a (pj); // Start array

	for (int i = 0; i < tools->n_tools; i++) {
		const R2AI_Tool *tool = &tools->tools[i];
		if (!tool->name) {
			continue;
		}

		pj_o (pj); // Start tool object
		pj_ks (pj, "type", "function");

		pj_k (pj, "function");
		pj_o (pj); // Start function object

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
		if (i < tools->n_tools - 1) {
			pj_raw (pj, ",");
		}
	}

	pj_end (pj); // End array

	char *result = pj_drain (pj);
	R_LOG_DEBUG ("OpenAI tools JSON: %s", result);
	return result;
}

// Function to convert R2AI_Tools to Anthropic format JSON
R_API char *r2ai_tools_to_anthropic_json(const R2AI_Tools *tools) {
	if (!tools || tools->n_tools <= 0) {
		return NULL;
	}

	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}

	pj_a (pj); // Start array

	for (int i = 0; i < tools->n_tools; i++) {
		const R2AI_Tool *tool = &tools->tools[i];
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
		if (i < tools->n_tools - 1) {
			pj_raw (pj, ",");
		}
	}

	pj_end (pj); // End array

	char *result = pj_drain (pj);
	return result;
}

// Function to free a tools structure
R_API void r2ai_tools_free(R2AI_Tools *tools) {
	if (!tools) {
		return;
	}

	if (tools->tools) {
		for (int i = 0; i < tools->n_tools; i++) {
			R2AI_Tool *tool = &tools->tools[i];
			R_FREE (tool->name);
			R_FREE (tool->description);
			R_FREE (tool->parameters);
		}
		R_FREE (tools->tools);
	}

	R_FREE (tools);
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

R_API char *r2ai_r2cmd(RCore *core, RJson *args, bool hide_tool_output, char **edited_command) {
	if (!args) {
		return strdup ("{ \"res\":\"Command is NULL\" }");
	}

	const RJson *command_json = r_json_get (args, "command");
	if (!command_json || !command_json->str_value) {
		return strdup ("{ \"res\":\"No command in tool call arguments\" }");
	}

	const char *command = command_json->str_value;

	if (r_str_startswith (command, "r2 ")) {
		return strdup ("{ \"res\":\"You are already in r2!\" }");
	}

	bool ask_to_execute = r_config_get_b (core->config, "r2ai.auto.yolo") != true;
	*edited_command = NULL; // keeps track of the command that was really executed in case user modifies it

	if (ask_to_execute) {
		// Check if command contains newlines to determine if it's multi-line
		bool is_multiline = strchr (command, '\n') != NULL;

		if (is_multiline) {
			// Use editor for multi-line commands
			*edited_command = strdup (command);
			r_cons_editor (core->cons, NULL, *edited_command);
			command = *edited_command;
		} else {
			// For single-line commands, push the command to input buffer
			R2_NEWLINE ();
			// Push the command to the input buffer

			// Get user input with command pre-filled
			r_cons_readpush (core->cons, command, strlen (command));
			r_cons_readpush (core->cons, "\x05", 1); // Ctrl+E - move to end
			const char *readline_result = r_line_readline (core->cons);
			// Check if interrupted or ESC pressed (readline_result is NULL or empty)
			if (R2_INTERRUPTED () || R_STR_ISEMPTY (readline_result)) {
				R_LOG_INFO ("Command execution cancelled %s", readline_result);
				return strdup ("R2AI_SIGINT");
			}

			// Process the result
			if (R_STR_ISNOTEMPTY (readline_result)) {
				*edited_command = strdup (readline_result);
				command = *edited_command;
			} else {
				// If user just pressed enter, keep the original command
				*edited_command = strdup (command);
				command = *edited_command;
			}
		}
		R_LOG_DEBUG ("Edited command: %s", *edited_command);
	} else {
		*edited_command = strdup (command);
	}

	if (!hide_tool_output) {
		char *red_command = r_str_newf ("\x1b[31m%s\x1b[0m\n", *edited_command);
		R2_PRINTF ("%s", red_command);
		R2_FLUSH ();
		free (red_command);
	}

	char *json_cmd = to_cmd (*edited_command);
	if (!json_cmd) {
		// caller should free edited_command
		return strdup ("{ \"res\":\"Failed to create JSON command\" }");
	}

	char *cmd_output = r_core_cmd_str (core, json_cmd);
	free (json_cmd);

	if (!cmd_output) {
		return strdup ("{ \"res\":\"Command returned no output or failed\" }");
	}

	return cmd_output;
}

// qjs function implementation
R_API char *r2ai_qjs(RCore *core, RJson *args, bool hide_tool_output) {
	if (!args) {
		return strdup ("{ \"res\":\"Script is NULL\" }");
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
			const char *readline_result = r_line_readline (core->cons);

			// Check if interrupted or ESC pressed (readline_result is NULL or empty)
			if (R2_INTERRUPTED () || R_STR_ISEMPTY (readline_result)) {
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

	if (!hide_tool_output) {
		char *print_script = r_str_newf ("\n```js\n%s\n```", script);
		char *print_script_rendered = r2ai_markdown (print_script);
		R2_PRINTF ("%s\n", print_script_rendered);
		R2_FLUSH ();
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

R_API char *execute_tool(RCore *core, const char *tool_name, const char *args, char **edited_command) {
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
		tool_result = r2ai_r2cmd (core, args_json, hide_tool_output, edited_command);
	} else if (strcmp (tool_name, "execute_js") == 0) {
		tool_result = r2ai_qjs (core, args_json, hide_tool_output);
	} else {
		tool_result = strdup ("{ \"res\":\"Unknown tool\" }");
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
		result = strdup (tool_result);
		free (tool_result);
		return result;
	}

	// Try to parse the JSON safely
	RJson *json = r_json_parse (tool_result);

	if (!json) {
		// JSON parsing failed, return original content
		R_LOG_WARN ("Failed to parse JSON response from tool execution");
		result = strdup (tool_result);
		free (tool_result);
		return result;
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
		R2_NEWLINE ();
		R2_PRINTF ("%s\n", result);
		R2_NEWLINE ();
		R2_FLUSH ();
	}

	r_str_ansi_strip (result);

	r_json_free (args_json);
	return result;
}
