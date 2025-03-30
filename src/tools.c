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

// Create a global tools structure with our tools
static R2AI_Tools r2ai_tools_instance = {
	.tools = &r2cmd_tool,
	.n_tools = 1
};

// Function to get the global tools instance
R_API const R2AI_Tools *r2ai_get_tools (void) {
	return &r2ai_tools_instance;
}

// Function to parse input tools_json (OpenAI format) into R2AI_Tool array
R_API R2AI_Tools *r2ai_tools_parse (const char *tools_json) {
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
	if (!tools) {
		r_json_free (json);
		return NULL;
	}

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
R_API char *r2ai_tools_to_openai_json (const R2AI_Tools *tools) {
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
	}

	pj_end (pj); // End array

	char *result = pj_drain (pj);
	return result;
}

// Function to convert R2AI_Tools to Anthropic format JSON
R_API char *r2ai_tools_to_anthropic_json (const R2AI_Tools *tools) {
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
	}

	pj_end (pj); // End array

	char *result = pj_drain (pj);
	return result;
}

// Function to free a tools structure
R_API void r2ai_tools_free (R2AI_Tools *tools) {
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

// r2cmd function implementation
R_API char *r2ai_r2cmd (RCore *core, const char *command) {
	if (!command) {
		return strdup ("Command is NULL");
	}

	if (r_str_startswith (command, "r2 ")) {
		return strdup ("You are already in r2!");
	}

	// Format the command as JSON with proper escaping (equivalent to json.dumps in Python)
	PJ *pj = pj_new ();
	if (!pj) {
		return strdup ("Failed to create JSON object");
	}

	pj_o (pj);
	pj_ks (pj, "cmd", command);
	pj_end (pj);

	char *json_cmd = pj_drain (pj);
	if (!json_cmd) {
		return strdup ("Failed to create JSON command");
	}

	char *cmd_output = r_core_cmd_str (core, json_cmd);
	free (json_cmd);

	if (!cmd_output) {
		return strdup ("Command returned no output or failed");
	}

	// Try to parse as JSON (equivalent to json.loads in Python)
	char *result = NULL;
	RJson *json = r_json_parse (cmd_output);

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
				result = strdup (cmd_output);
			}
		}

		r_json_free (json);
	} else {
		// JSON parse failed, handle like JSONDecodeError in Python
		char *trimmed = r_str_trim_dup (cmd_output);
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
						result = strdup (cmd_output);
					}
				} else {
					result = strdup (cmd_output);
				}
				r_list_free (lines);
			} else {
				result = strdup (cmd_output);
			}
			free (trimmed);
		} else {
			result = strdup (cmd_output);
		}
	}

	free (cmd_output);

	if (!result) {
		return r_str_newf ("Error running r2cmd: Unknown error\nCommand: %s", command);
	}

	return result;
}