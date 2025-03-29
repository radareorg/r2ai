#include "r2ai.h"

// Forward declaration of the r2ai_llmcall function
extern R2AI_Message *r2ai_llmcall (RCore *core, R2AIArgs args);

const char *Gprompt_auto = "You are a reverse engineer and you are using radare2 to analyze a binary.\n"
			   "The user will ask questions about the binary and you will respond with the answer to the best of your ability.\n"
			   "\n"
			   "# Guidelines\n"
			   "- Understand the Task: Grasp the main objective, goals, requirements, constraints, and expected output.\n"
			   "- Reasoning Before Conclusions**: Encourage reasoning steps before any conclusions are reached.\n"
			   "- Assume the user is always asking you about the binary, unless they're specifically asking you for radare2 help.\n"
			   "- The binary has already been loaded. You can interact with the binary using the r2cmd tool.\n"
			   "- `this` or `here` might refer to the current address in the binary or the binary itself.\n"
			   "- If you need more information, try to use the r2cmd tool to run commands before answering.\n"
			   "- You can use the r2cmd tool multiple times if you need or you can pass a command with pipes if you need to chain commands.\n"
			   "- If you're asked to decompile a function, make sure to return the code in the language you think it was originally written and rewrite it to be as easy as possible to be understood. Make sure you use descriptive variable and function names and add comments.\n"
			   "- Don't just regurgitate the same code, figure out what it's doing and rewrite it to be more understandable.\n"
			   "- If you need to run a command in r2 before answering, you can use the r2cmd tool\n"
			   "- Do not repeat commands if you already know the answer.\n"
			   "- Formulate a plan. Think step by step. Analyze the binary as much as possible before answering.\n"
			   "- You must keep going until you have a final answer.\n"
			   "- Double check that final answer. Make sure you didn't miss anything.\n"
			   "- Make sure you call tools and functions correctly.\n";

// Helper function to process messages and handle tool calls recursively
static void process_messages (RCore *core, R2AI_Messages *messages) {
	char *error = NULL;

	// Set up args for r2ai_llmcall call with tools directly
	R2AIArgs args = {
		.messages = messages,
		.error = &error,
		.dorag = true,
		.tools = r2ai_get_tools ()
	};

	// Call r2ai_llmcall to get a response
	R2AI_Message *response = r2ai_llmcall (core, args);

	if (!response) {
		if (error) {
			R_LOG_ERROR ("Error: %s", error);
			free (error);
		} else {
			R_LOG_ERROR ("Unknown error occurred");
		}
		return;
	}

	// Process the response - we need to add it to our messages array
	if (response->content) {
		R_LOG_INFO ("Assistant response: %s", response->content);
		r_cons_printf ("%s\n", response->content);
		r_cons_flush ();
	}

	// Add the response to our messages array
	// This creates a copy, so we can safely free the original later
	r2ai_msgs_add (messages, response);

	// Check for tool calls and process them
	if (response->tool_calls && response->n_tool_calls > 0) {
		R_LOG_INFO ("Found %d tool calls", response->n_tool_calls);

		// Process each tool call
		for (int i = 0; i < response->n_tool_calls; i++) {
			const R2AI_ToolCall *tool_call = &response->tool_calls[i];
			// Parse arguments JSON to get the command for printing
			char *args_copy_for_print = strdup (tool_call->arguments);
			RJson *args_json_for_print = r_json_parse (args_copy_for_print);
			if (args_json_for_print) {
				const RJson *command_json_for_print = r_json_get (args_json_for_print, "command");
				if (command_json_for_print && command_json_for_print->str_value) {
					r_cons_printf ("\x1b[1;32m> \x1b[4m%s\x1b[0m\n", command_json_for_print->str_value);
					r_cons_flush ();
				}
				r_json_free (args_json_for_print);
			}
			free (args_copy_for_print);

			if (!tool_call->name || !tool_call->arguments || !tool_call->id) {
				continue;
			}

			// We only support the r2cmd function for now
			if (strcmp (tool_call->name, "r2cmd") == 0) {
				// Parse arguments JSON to get the command
				char *args_copy = strdup (tool_call->arguments);
				RJson *args_json = r_json_parse (args_copy);
				if (!args_json) {
					R_LOG_ERROR ("Failed to parse tool call arguments");
					free (args_copy);
					continue;
				}

				const RJson *command_json = r_json_get (args_json, "command");
				if (!command_json || !command_json->str_value) {
					R_LOG_ERROR ("No command in tool call arguments");
					r_json_free (args_json);
					free (args_copy);
					continue;
				}

				const char *command = command_json->str_value;
				R_LOG_INFO ("Running command: %s", command);
				// Format the command as JSON with proper escaping
				char *escaped_command = r_str_escape (command);
				if (!escaped_command) {
					R_LOG_ERROR ("Failed to escape command for JSON");
					r_json_free (args_json);
					free (args_copy);
					continue;
				}

				char *formatted_cmd = r_str_newf ("{\"cmd\":\"%s\"}", escaped_command);
				R_LOG_INFO ("Formatted command: %s", formatted_cmd);
				free (escaped_command);
				free (formatted_cmd); // Free formatted_cmd to prevent memory leak

				// Use the original command for execution, not the formatted one
				// TODO: make it -e scr.color=0 and back to original setting
				char *cmd_output = r_core_cmd_str (core, command);
				r_cons_printf ("%s", cmd_output);
				r_cons_flush ();
				r_json_free (args_json);
				free (args_copy);

				if (!cmd_output) {
					cmd_output = strdup ("Command returned no output or failed");
				}

				// Create a tool call response message
				R2AI_Message tool_response = {
					.role = "tool",
					.tool_call_id = tool_call->id,
					.content = cmd_output
				};

				// Add the tool response to our messages array
				r2ai_msgs_add (messages, &tool_response);

				free (cmd_output);
			}
		}

		// Call process_messages recursively with the updated messages
		process_messages (core, messages);
	}

	// Free the response - the strings were already copied to messages array
	r2ai_message_free (response);
	// Free the response struct itself since r2ai_message_free doesn't do it anymore
	free (response);
}

R_IPI void cmd_r2ai_a (RCore *core, const char *user_query) {
	// Create a new messages array
	R2AI_Messages *messages = r2ai_msgs_new ();
	if (!messages) {
		R_LOG_ERROR ("Failed to create messages array");
		return;
	}

	// Add system message
	R2AI_Message system_msg = {
		.role = "system",
		.content = Gprompt_auto
	};
	r2ai_msgs_add (messages, &system_msg);

	// Add user query
	R2AI_Message user_msg = {
		.role = "user",
		.content = user_query
	};
	r2ai_msgs_add (messages, &user_msg);

	// Process messages
	process_messages (core, messages);

	// Free messages array
	r2ai_msgs_free (messages);
}
