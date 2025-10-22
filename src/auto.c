#include "r2ai.h"

// Stats are now stored in R2AI_State->stats, no longer need global variable

// Helper function to format time duration
static char *format_time_duration(time_t seconds) {
	if (seconds < 60) {
		return r_str_newf ("%" PFMT64d "s", (long long)seconds);
	}
	if (seconds < 3600) {
		return r_str_newf ("%" PFMT64d "m%" PFMT64d "s", (long long) (seconds / 60), (long long) (seconds % 60));
	}
	return r_str_newf ("%" PFMT64d "h%" PFMT64d "m%" PFMT64d "s",
		(long long) (seconds / 3600),
		(long long) ((seconds % 3600) / 60),
		(long long) (seconds % 60));
}

// Initialize timing and cost tracking for a run
static void r2ai_stats_init_run(R2AI_State *state, int n_run) {
	time_t run_start = time (NULL);
	if (n_run == 1) {
		// First run, initialize total timing
		state->stats.total_cost = 0.0;
		state->stats.run_cost = 0.0;
		state->stats.total_start_time = run_start;
		state->stats.total_tokens = 0;
		state->stats.run_tokens = 0;
		state->stats.total_prompt_tokens = 0;
		state->stats.run_prompt_tokens = 0;
		state->stats.total_completion_tokens = 0;
		state->stats.run_completion_tokens = 0;
	}
	state->stats.start_time = run_start;
}

// Print a simple run indicator at the start
static void r2ai_print_run_end(RCorePluginSession *cps, const R2AI_Usage *usage, int n_run, int max_runs) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	(void)n_run;
	(void)max_runs;
	time_t run_time = time (NULL) - state->stats.start_time;
	time_t total_time = time (NULL) - state->stats.total_start_time;
	if (usage) {
		state->stats.run_tokens = usage->total_tokens;
		state->stats.run_prompt_tokens = usage->prompt_tokens;
		state->stats.run_completion_tokens = usage->completion_tokens;
		state->stats.total_tokens += usage->total_tokens;
		state->stats.total_prompt_tokens += usage->prompt_tokens;
		state->stats.total_completion_tokens += usage->completion_tokens;
	}

	if (r_config_get_b (core->config, "r2ai.chat.show_cost") == true) {
		// TODO: calculate cost
		state->stats.run_cost = 0.0 * run_time;
		state->stats.total_cost += state->stats.run_cost;
	}

	// Format times for display
	char *run_time_str = format_time_duration (run_time);
	char *total_time_str = format_time_duration (total_time);

	// Print detailed stats
	R2_PRINTF ("\x1b[1;34m%s | total: %d in: %d out: %d | run: %d in: %d out: %d | %s / %s\x1b[0m\n",
		r_config_get (core->config, "r2ai.model"),
		state->stats.total_tokens,
		state->stats.total_prompt_tokens,
		state->stats.total_completion_tokens,
		state->stats.run_tokens,
		state->stats.run_prompt_tokens,
		state->stats.run_completion_tokens,
		run_time_str,
		total_time_str);
	R2_NEWLINE ();
	R2_FLUSH ();

	free (run_time_str);
	free (total_time_str);
}

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
R_API void process_messages(RCorePluginSession *cps, R2AI_Messages *messages, const char *system_prompt, int n_run) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	char *error = NULL;
	bool interrupted = false;
	const int max_runs = r_config_get_i (core->config, "r2ai.auto.max_runs");

	if (n_run > max_runs) {
		R2_PRINTF ("\x1b[1;31m[r2ai] Max runs reached\x1b[0m\n");
		R2_FLUSH ();
		return;
	}

	if (!system_prompt) {
		system_prompt = Gprompt_auto;
		const char *init_commands = r_config_get (core->config, "r2ai.auto.init_commands");
		if (R_STR_ISNOTEMPTY (init_commands)) {
			char *edited_command = NULL;
			char *cmd_output = execute_tool (core, "r2cmd", r_str_newf ("{\"command\":\"%s\"}", init_commands), &edited_command);
			if (R_STR_ISNOTEMPTY (cmd_output)) {
				R2AI_Message init_msg = {
					.role = "system",
					.content = r_str_newf ("Here is some information about the binary to get you started:\n>%s\n%s", edited_command, cmd_output)
				};
				r2ai_msgs_add (messages, &init_msg);
				free (cmd_output);
			}
			free (edited_command);
		}
	}

	r2ai_stats_init_run (state, n_run);

	R2_PRINTF ("\x1b[35m[DEBUG] About to call r2ai_llmcall with n_run=%d\x1b[0m\n", n_run);
	R2_FLUSH ();

	// Set up args for r2ai_llmcall call with tools directly
	R2AIArgs args = {
		.messages = messages,
		.error = &error,
		.dorag = true,
		.tools = r2ai_get_tools (), // Always send tools in auto mode
		.system_prompt = system_prompt
	};

	R2AI_ChatResponse *response = r2ai_llmcall (cps, args);

	if (!response) {
		return;
	}

	const R2AI_Message *message = response->message;
	const R2AI_Usage *usage = response->usage;

	if (!message) {
		R_LOG_ERROR ("No message in response");
		free (response);
		return;
	}

	// Debug logging for rawtools
	R_LOG_DEBUG ("[DEBUG] Model response - Role: %s", message->role? message->role: "null");
	if (message->content) {
		R_LOG_DEBUG ("[DEBUG] Content: %s", message->content);
	}
	if (message->reasoning_content) {
		R_LOG_DEBUG ("[DEBUG] Reasoning: %s", message->reasoning_content);
	}
	if (message->tool_calls && message->n_tool_calls > 0) {
		R_LOG_DEBUG ("[DEBUG] Tool calls: %d", message->n_tool_calls);
		for (int i = 0; i < message->n_tool_calls; i++) {
			const R2AI_ToolCall *tc = &message->tool_calls[i];
			R_LOG_DEBUG ("[DEBUG] Tool %d: %s - %s", i, tc->name? tc->name: "null", tc->arguments? tc->arguments: "null");
		}
	}

	// Process the response - we need to add it to our messages array
	if (message->content || message->reasoning_content) {
		R2_PRINTF ("\x1b[31m[Assistant]\x1b[0m\n\n");
		if (message->reasoning_content) {
			R2_PRINTF ("\x1b[90m<thinking>\n%s\n</thinking>\x1b[0m\n", message->reasoning_content);
			R2_NEWLINE ();
			R2_FLUSH ();
		}
		if (message->content) {
			R2_PRINTF ("%s", message->content);
			R2_NEWLINE ();
			R2_FLUSH ();
		}
	}

	// Add the response to our messages array
	// This creates a copy, so we can safely free the original later
	r2ai_msgs_add (messages, message);

	// Check for tool calls and process them
	if (message->tool_calls && message->n_tool_calls > 0) {
		R_LOG_DEBUG ("Found %d tool call(s)", message->n_tool_calls);

		// Process each tool call
		for (int i = 0; i < message->n_tool_calls; i++) {
			const R2AI_ToolCall *tool_call = &message->tool_calls[i];

			if (!tool_call->name || !tool_call->arguments || !tool_call->id) {
				R_LOG_DEBUG ("Skipping invalid tool call %d", i);
				continue;
			}
			R_LOG_DEBUG ("Tool call %d: %s with args: %s", i, tool_call->name, tool_call->arguments);
			// Don't log the full arguments which might get truncated
			char *tool_name = strdup (tool_call->name);
			char *tool_args = strdup (tool_call->arguments);
			if (!tool_name || !tool_args) {
				R_LOG_ERROR ("Failed to allocate memory for tool call");
				free (tool_name);
				free (tool_args);
				continue;
			}

			char *cmd_output = NULL;
			if (interrupted) {
				cmd_output = strdup ("<user interrupted>");
			} else {
				char *edited_command = NULL;
				cmd_output = execute_tool (core, tool_name, tool_args, &edited_command);
				if (edited_command) {
					// Update the last message's tool call arguments with the edited command
					R2AI_Message *last_msg = r_list_get_n (messages->messages, r_list_length (messages->messages) - 1);
					if (last_msg && last_msg->tool_calls && last_msg->n_tool_calls > 0) {
						for (int j = 0; j < last_msg->n_tool_calls; j++) {
							R2AI_ToolCall *tc = (R2AI_ToolCall *)&last_msg->tool_calls[j];
							if (tc->id && strcmp (tc->id, tool_call->id) == 0) {
								// For r2cmd, update the command in arguments
								if (strcmp (tool_name, "r2cmd") == 0) {
									char *args_dup = strdup (tc->arguments);
									RJson *args_json = r_json_parse (args_dup);
									if (args_json) {
										RJson *cmd_json = (RJson *)r_json_get (args_json, "command");
										if (cmd_json && cmd_json->str_value) {
											// Update the command field
											free ((char *)cmd_json->str_value);
											cmd_json->str_value = strdup (edited_command);
											// Serialize back to JSON
											char *new_args = r_json_to_string (args_json);
											if (new_args) {
												free ((void *)tc->arguments);
												tc->arguments = new_args;
											}
										}
										r_json_free (args_json);
									}
								}
								break;
							}
						}
					}
				}
				free (edited_command);
			}

			free (tool_name);
			free (tool_args);
			if (strcmp (cmd_output, "R2AI_SIGINT") == 0) {
				R2_PRINTF ("\n\n\x1b[1;31m[r2ai] Processing interrupted after tool execution\x1b[0m\n\n");
				R2_FLUSH ();
				free (cmd_output);
				cmd_output = strdup ("<user interrupted>");
				interrupted = true;
			}

			// Create a tool call response message
			R2AI_Message tool_response = {
				.role = "tool",
				.tool_call_id = strdup (tool_call->id),
				.content = cmd_output
			};

			// Add the tool response to our messages array
			r2ai_msgs_add (messages, &tool_response);
			R_LOG_DEBUG ("[DEBUG] Added tool response to messages: %s", cmd_output? cmd_output: "null");
			R2_PRINTF ("\x1b[32m[DEBUG] Tool result: %s\x1b[0m\n", cmd_output? cmd_output: "no output");
			free (cmd_output);
		}

		r2ai_print_run_end (cps, usage, n_run, max_runs);

		// Check if we should continue with recursion
		if (!interrupted && message->tool_calls && message->n_tool_calls > 0) {
			R_LOG_DEBUG ("[DEBUG] Recursing to process_messages with n_run=%d", n_run + 1);
			process_messages (cps, messages, system_prompt, n_run + 1);
		} else {
			R_LOG_DEBUG ("[DEBUG] Auto mode loop ending - no more tool calls or interrupted");
		}
	} else {
		r2ai_print_run_end (cps, usage, n_run, max_runs);
	}

	// Free the response struct itself since r2ai_message_free doesn't do it anymore
	free (response);
}

R_IPI void cmd_r2ai_a(RCorePluginSession *cps, const char *user_query) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	R2_PRINTF ("\x1b[35m[DEBUG] cmd_r2ai_a called with query: %s\x1b[0m\n", user_query);
	R2_FLUSH ();
	// Get conversation
	R2AI_Messages *messages = r2ai_conversation_get (state);
	if (!messages) {
		R_LOG_ERROR ("Conversation not initialized");
		return;
	}

	// Add user query to the conversation (no system prompt)
	// If this is the first message in a new conversation, clear previous history
	if (r_list_length (messages->messages) == 0 || r_config_get_b (core->config, "r2ai.auto.reset_on_query")) {
		r2ai_msgs_clear (messages);
	}

	// Add user query
	R2AI_Message user_msg = {
		.role = "user",
		.content = (char *)user_query
	};
	r2ai_msgs_add (messages, &user_msg);

	process_messages (cps, messages, NULL, 1);
}

// Helper function to display content with length indication for long content
static void print_content_with_length(RCore *core, const char *content, const char *empty_msg, bool always_show_length) {
	if (!content || *content == '\0') {
		R2_PRINTF ("%s\n", empty_msg? empty_msg: "<no content>");
		return;
	}

	size_t content_len = strlen (content);
	const size_t max_display = 200;

	if (content_len > max_display) {
		// Truncate long content and show length
		char *truncated = r_str_ndup (content, max_display);
		R2_PRINTF ("%s... \x1b[1;37m(length: %zu chars)\x1b[0m\n",
			truncated, content_len);
		free (truncated);
	} else if (always_show_length) {
		// Always show length for certain types (like tool responses)
		R2_PRINTF ("%s \x1b[1;37m(length: %zu chars)\x1b[0m\n",
			content, content_len);
	} else {
		R2_PRINTF ("%s\n", content);
	}
}

// Add this function right after cmd_r2ai_a
R_IPI void cmd_r2ai_logs(RCorePluginSession *cps) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	// Get conversation
	R2AI_Messages *messages = r2ai_conversation_get (state);
	if (!messages || r_list_length (messages->messages) == 0) {
		R2_PRINTF ("No conversation history available\n");
		return;
	}

	const char *input = r_core_cmd_str (core, "r2ai");
	bool json_mode = input && strstr (input, "-Lj");
	free ((char *)input);

	if (json_mode) {
		PJ *pj = pj_new ();
		if (!pj) {
			return;
		}

		pj_a (pj);

		for (int i = 0; i < r_list_length (messages->messages); i++) {
			const R2AI_Message *msg = r_list_get_n (messages->messages, i);
			pj_o (pj);
			pj_ks (pj, "role", msg->role? msg->role: "unknown");
			pj_ks (pj, "content", msg->content? msg->content: "");
			if (msg->tool_calls && msg->n_tool_calls > 0) {
				pj_ka (pj, "tool_calls");
				for (int j = 0; j < msg->n_tool_calls; j++) {
					const R2AI_ToolCall *tc = &msg->tool_calls[j];
					pj_o (pj);
					if (tc->name) {
						pj_ks (pj, "name", tc->name);
					}
					if (tc->arguments) {
						pj_ks (pj, "arguments", tc->arguments);
					}
					pj_end (pj);
				}
				pj_end (pj);
			}
			pj_end (pj);
		}

		pj_end (pj);

		char *json_str = pj_drain (pj);
		R2_PRINTF ("%s\n", json_str);
		free (json_str);

		return;
	}

	R2_PRINTF ("\x1b[1;34m[r2ai] Chat Logs (%d messages)\x1b[0m\n",
		r_list_length (messages->messages));

	R2_PRINTF ("\x1b[1;33mNote: System prompt is applied automatically but not stored in history\x1b[0m\n\n");

	// Display each message in the conversation
	for (int i = 0; i < r_list_length (messages->messages); i++) {
		const R2AI_Message *msg = r_list_get_n (messages->messages, i);
		const char *role = msg->role;

		// Format based on role
		if (!strcmp (role, "user")) {
			R2_PRINTF ("\x1b[1;32m[user]:\x1b[0m ");
			print_content_with_length (core, msg->content, "<no content>", false);
		} else if (!strcmp (role, "assistant")) {
			R2_PRINTF ("\x1b[1;36m[assistant]:\x1b[0m ");
			print_content_with_length (core, msg->content, "<no content>", false);
			// Show tool calls if present
			if (msg->tool_calls && msg->n_tool_calls > 0) {
				for (int j = 0; j < msg->n_tool_calls; j++) {
					const R2AI_ToolCall *tc = &msg->tool_calls[j];
					R2_PRINTF ("  \x1b[1;35m[tool call]:\x1b[0m %s\n",
						tc->name? tc->name: "<unnamed>");

					if (tc->arguments) {
						R2_PRINTF ("    %s\n", tc->arguments);
					}
				}
			}
		} else if (!strcmp (role, "tool")) {
			R2_PRINTF ("\x1b[1;35m[tool]:\x1b[0m ");
			print_content_with_length (core, msg->content, "<no result>", true);

			// Don't show the tool call ID as requested
		} else {
			// Other roles (system, etc.)
			R2_PRINTF ("\x1b[1;37m[%s]:\x1b[0m ", role);
			print_content_with_length (core, msg->content, "<no content>", false);
		}

		R2_NEWLINE ();
		R2_FLUSH ();
	}
}
