/* r2ai - Copyright 2023-2025 pancake */

#define R_LOG_ORIGIN "rawtools"
#include "r2ai.h"
#include "r2ai_priv.h"

// Function to build the rawtools prompt with available tools
static const char *RAWTOOLS_PROMPT =
	"Common radare2 commands you can use with r2cmd:\n"
	"- i: Show binary information\n"
	"- iI: Show detailed binary info\n"
	"- iz: Show strings\n"
	"- afl: List functions\n"
	"- pdf @ function: Disassemble function\n"
	"- px @ address: Show hexdump\n"
	"- aaa: Analyze all\n"
	"- s address: Seek to address\n"
	"- ? command: Get help\n\n"
	"To run radare2 commands, use the r2cmd tool with JSON arguments.\n\n"
	"TOOL: r2cmd\n"
	"USAGE: TOOL: r2cmd {\"command\": \"your_command_here\"}\n\n"
	"Example: TOOL: r2cmd {\"command\": \"i\"}\n\n"
	"If you don't need to run commands, just answer directly.\n\n";

// Function to parse raw tool call from response text
static bool parse_raw_tool_call(const char *response, char **tool_name, char **tool_args) {
	if (!response || !tool_name || !tool_args) {
		return false;
	}

	*tool_name = NULL;
	*tool_args = NULL;

	// First try to parse "TOOL: " format
	const char *tool_prefix = "TOOL: ";
	const char *line_start = response;

	while ((line_start = strstr (line_start, tool_prefix))) {
		// Check if it's at the beginning of a line
		if (line_start == response || *(line_start - 1) == '\n') {
			// Found a tool call
			const char *tool_start = line_start + strlen (tool_prefix);
			const char *space_pos = strchr (tool_start, ' ');

			if (space_pos) {
				// Extract tool name
				size_t name_len = space_pos - tool_start;
				*tool_name = r_str_ndup (tool_start, name_len);

				// Extract arguments (rest of the line)
				*tool_args = strdup (space_pos + 1);

				// Trim whitespace from arguments (simple implementation)
				if (*tool_args) {
					char *start = *tool_args;
					while (*start && (*start == ' ' || *start == '\t')) {
						start++;
					}
					char *end = start + strlen (start) - 1;
					while (end > start && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
						end--;
					}
					*(end + 1) = '\0';
					if (start != *tool_args) {
						memmove (*tool_args, start, strlen (start) + 1);
					}
				}

				return true;
			}
		}
		line_start += strlen (tool_prefix);
	}

	// If no TOOL: format found, try to parse JSON response
	// Look for JSON that looks like tool arguments
	const char *json_start = strstr (response, "{\"command\"");
	if (json_start) {
		*tool_name = strdup ("r2cmd");
		*tool_args = strdup (json_start);
		// Trim trailing whitespace and newlines
		char *end = *tool_args + strlen (*tool_args) - 1;
		while (end > *tool_args && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
			*end = '\0';
			end--;
		}
		return true;
	}

	return false;
}

// Function to handle rawtools mode in LLM call
R2AI_ChatResponse *r2ai_rawtools_llmcall(RCorePluginSession *cps, R2AIArgs args) {
	if (!cps) {
		return NULL;
	}
	RCore *core = cps->core;

	// Modify the system prompt to include rawtools instructions only if no tool messages
	const char *original_system_prompt = args.system_prompt;

	// For rawtools, use a shorter system prompt to avoid token limits
	const char *short_system_prompt = "You are a reverse engineer using radare2. The binary is loaded. Use r2cmd tool for analysis.";

	// Check for initial command output in messages
	char *init_output = NULL;
	if (args.messages && args.messages->messages) {
		RList *msgs = args.messages->messages;
		int n_msgs = r_list_length (msgs);
		for (int i = 0; i < n_msgs; i++) {
			R2AI_Message *msg = r_list_get_n (msgs, i);
			if (msg && msg->role && !strcmp (msg->role, "system") && msg->content &&
				strstr (msg->content, "Here is some information about the binary")) {
				init_output = strdup (msg->content);
				break;
			}
		}
	}

	char *enhanced_system_prompt = NULL;
	if (init_output) {
		enhanced_system_prompt = r_str_newf ("%s\n\n%s\n\n%s", short_system_prompt, init_output, RAWTOOLS_PROMPT);
	} else {
		enhanced_system_prompt = r_str_newf ("%s\n\n%s", short_system_prompt, RAWTOOLS_PROMPT);
	}
	free (init_output);
	// Temporarily modify args to use enhanced prompt and no tools (since we're using prompt engineering)
	R2AIArgs rawtools_args = args;
	rawtools_args.system_prompt = enhanced_system_prompt;
	rawtools_args.tools = NULL; // Disable native tool calling

	// Make the LLM call directly to provider
	const char *provider = rawtools_args.provider? rawtools_args.provider: r_config_get (core->config, "r2ai.api");
	if (!provider) {
		R_LOG_ERROR ("No provider defined");
		return NULL;
	}

	R2AI_ChatResponse *response = NULL;
	const R2AIProvider *p = r2ai_get_provider (provider);
	if (p && p->uses_anthropic_header) {
		response = r2ai_anthropic (cps, rawtools_args);
	} else {
		response = r2ai_openai (cps, rawtools_args);
	}

	free (enhanced_system_prompt);

	if (!response || !response->message || !response->message->content) {
		return response;
	}

	R_LOG_DEBUG ("[RAWTOOLS] Raw model response: %s", response->message->content);

	// Check if the response contains a raw tool call
	char *tool_name = NULL;
	char *tool_args = NULL;

	if (parse_raw_tool_call (response->message->content, &tool_name, &tool_args)) {
		R_LOG_DEBUG ("Raw tool call detected: %s with args: %s", tool_name, tool_args);

		// Find the tool in our tools list
		const R2AI_Tools *tools = r2ai_get_tools ();
		bool tool_found = false;

		for (int i = 0; i < tools->n_tools; i++) {
			if (tools->tools[i].name && !strcmp (tools->tools[i].name, tool_name)) {
				tool_found = true;
				break;
			}
		}

		if (tool_found) {
			// Modify the existing response to include tool call information
			R2AI_Message *modified_message = R_NEW0 (R2AI_Message);
			if (modified_message) {
				modified_message->role = strdup ("assistant");
				// Remove the TOOL line from content, or set to empty if that's all there is
				char *content = strdup (response->message->content? response->message->content: "");
				char *tool_line = strstr (content, "TOOL: ");
				if (tool_line) {
					// Find the end of the line
					char *line_end = strchr (tool_line, '\n');
					if (line_end) {
						// Remove the TOOL line
						memmove (tool_line, line_end + 1, strlen (line_end + 1) + 1);
					} else {
						// The TOOL line is the entire content
						*tool_line = '\0';
					}
				}
				modified_message->content = content;

				// Set up proper tool call structure
				modified_message->tool_calls = R_NEWS0 (R2AI_ToolCall, 1);
				if (modified_message->tool_calls) {
					modified_message->tool_calls[0].name = tool_name;
					modified_message->tool_calls[0].arguments = tool_args;
					char id_buf[32];
					snprintf (id_buf, sizeof (id_buf), "rawtool_%d", (int)time (NULL));
					modified_message->tool_calls[0].id = strdup (id_buf);
					modified_message->n_tool_calls = 1;
				}
				tool_name = NULL;
				tool_args = NULL;

				// Replace the response message
				if (response->message) {
					r2ai_message_free ((R2AI_Message *)response->message);
				}
				*(R2AI_Message **)&response->message = modified_message;
			}
		} else {
			// Unknown tool, modify content to indicate error
			R2AI_Message *modified_message = R_NEW0 (R2AI_Message);
			if (modified_message) {
				modified_message->role = strdup ("assistant");
				size_t result_len = strlen ("Unknown tool: ") + strlen (tool_name) + 1;
				modified_message->content = malloc (result_len);
				if (modified_message->content) {
					snprintf (modified_message->content, result_len, "Unknown tool: %s", tool_name);
				}

				// Replace the response message
				if (response->message) {
					r2ai_message_free ((R2AI_Message *)response->message);
				}
				*(R2AI_Message **)&response->message = modified_message;
			}
			free (tool_name);
			free (tool_args);
			tool_name = NULL;
			tool_args = NULL;
		}

		return response;
	}

	// No tool call found
	free (tool_name);
	free (tool_args);

	// If the response has no content, try again with normal mode (without rawtools prompt)
	if (!response->message || !response->message->content || !*response->message->content) {
		R_LOG_DEBUG ("No tool call found and no content, falling back to normal mode");

		// Free the current response
		if (response->message) {
			r2ai_message_free ((R2AI_Message *)response->message);
		}
		free (response);

		// Modify args to use original system prompt without rawtools enhancement
		R2AIArgs fallback_args = args;
		fallback_args.system_prompt = original_system_prompt;
		fallback_args.tools = args.tools; // Keep tools for fallback

		// Call provider directly
		const char *provider = fallback_args.provider? fallback_args.provider: r_config_get (core->config, "r2ai.api");
		if (!provider) {
			R_LOG_ERROR ("No provider defined");
			return NULL;
		}

		R2AI_ChatResponse *fallback_response = NULL;
		const R2AIProvider *p = r2ai_get_provider (provider);
		if (p && p->uses_anthropic_header) {
			fallback_response = r2ai_anthropic (cps, fallback_args);
		} else {
			fallback_response = r2ai_openai (cps, fallback_args);
		}

		if (fallback_response && fallback_response->message && fallback_response->message->content && *fallback_response->message->content) {
			return fallback_response;
		}

		// If still no content, create a response with warning
		if (fallback_response) {
			if (fallback_response->message) {
				r2ai_message_free ((R2AI_Message *)fallback_response->message);
			}
			free (fallback_response);
		}

		// Create a warning response
		R2AI_ChatResponse *warning_response = R_NEW0 (R2AI_ChatResponse);
		R2AI_Message *msg = R_NEW0 (R2AI_Message);
		msg->role = strdup ("assistant");
		msg->content = strdup ("Warning: LLM provided no response content");
		*((R2AI_Message **)&warning_response->message) = msg;
		R_LOG_WARN ("LLM provided no response content");
		return warning_response;
	}

	return response;
}
