/* Copyright r2ai - 2023-2026 - pancake */

#include "r2ai.h"

// Stats are now stored in R2AI_State->stats, no longer need global variable

// Helper function to format time duration
static char *format_time_duration(time_t seconds) {
	if (seconds < 60) {
		return r_str_newf ("%" PFMT64d "s", (ut64)seconds);
	}
	if (seconds < 3600) {
		return r_str_newf ("%" PFMT64d "m%" PFMT64d "s", (ut64) (seconds / 60), (ut64) (seconds % 60));
	}
	return r_str_newf ("%" PFMT64d "h%" PFMT64d "m%" PFMT64d "s",
		(ut64) (seconds / 3600),
		(ut64) ((seconds % 3600) / 60),
		(ut64) (seconds % 60));
}

// Initialize timing tracking for a run
static void r2ai_stats_init_run(R2AI_State *state, int n_run) {
	time_t run_start = time (NULL);
	if (n_run == 1) {
		// First run, initialize total timing
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

	// Format times for display
	char *run_time_str = format_time_duration (run_time);
	char *total_time_str = format_time_duration (total_time);

	// Print detailed stats
	r_cons_printf (core->cons, "\x1b[1" Color_BLUE "%s | total: %d in: %d out: %d | run: %d in: %d out: %d | %s / %s" Color_RESET "\n", r_config_get (core->config, "r2ai.model"), state->stats.total_tokens, state->stats.total_prompt_tokens, state->stats.total_completion_tokens, state->stats.run_tokens, state->stats.run_prompt_tokens, state->stats.run_completion_tokens, run_time_str, total_time_str);
	r_cons_newline (core->cons);
	r_cons_flush (core->cons);

	free (run_time_str);
	free (total_time_str);
}

// Helper function to handle final response attempt without tools
static void handle_final_response_attempt(RCorePluginSession *cps, RList *messages, const char *effective_prompt, char **error) {
	RCore *core = cps->core;
	if (r_cons_yesno (core->cons, 1, "Try to produce response without tool calling with collected information? (Y/n)")) {
		char *final_system_prompt = r_str_newf ("%s\n\nIMPORTANT: Do not use any tools. Provide a direct answer based on the collected information.", effective_prompt);
		R2AIArgs args_final = {
			.messages = messages,
			.error = error,
			.dorag = true,
			.tools = NULL, // No tools for final response
			.system_prompt = final_system_prompt
		};

		R2AI_ChatResponse *final_response = r2ai_llmcall (cps, args_final);
		if (final_response && final_response->message) {
			const R2AI_Message *final_msg = final_response->message;
			r_cons_printf (core->cons, Color_RED "[Assistant]" Color_RESET);
			if (final_msg->reasoning_content) {
				r_cons_printf (core->cons, Color_GRAY "<thinking>\n%s\n</thinking>" Color_RESET "\n", final_msg->reasoning_content);
				r_cons_newline (core->cons);
				r_cons_flush (core->cons);
			}
			if (final_msg->content) {
				r_cons_printf (core->cons, "%s", final_msg->content);
				r_cons_newline (core->cons);
				r_cons_flush (core->cons);
			}
			// Add final response to messages for completeness
			r2ai_msgs_add (messages, final_msg);
			free (final_response);
		}
		free (final_system_prompt);
	} else {
		r_cons_printf (core->cons, "Auto mode interrupted without final response.\n");
		r_cons_flush (core->cons);
	}
}

static void update_tool_call_argument(R2AI_Message *msg, const char *tool_call_id, const char *field_name, const char *field_value) {
	R_RETURN_IF_FAIL (msg && tool_call_id && field_name && field_value);
	if (!msg->tool_calls || r_list_empty (msg->tool_calls)) {
		return;
	}
	RListIter *iter;
	R2AI_ToolCall *tc;
	r_list_foreach (msg->tool_calls, iter, tc) {
		if (!tc->id || strcmp (tc->id, tool_call_id) || !tc->arguments) {
			continue;
		}
		char *args_dup = strdup (tc->arguments);
		if (!args_dup) {
			return;
		}
		RJson *args_json = r_json_parse (args_dup);
		if (!args_json) {
			free (args_dup);
			return;
		}
		RJson *field_json = (RJson *)r_json_get (args_json, field_name);
		if (field_json && field_json->str_value) {
			const char *orig_value = field_json->str_value;
			field_json->str_value = field_value;
			char *new_args = r_json_to_string (args_json);
			field_json->str_value = orig_value;
			if (new_args) {
				free ((void *)tc->arguments);
				tc->arguments = new_args;
			}
		}
		r_json_free (args_json);
		free (args_dup);
		return;
	}
}

static const char *auto_prompt_get(R2AI_State *state) {
	return (state && R_STR_ISNOTEMPTY (state->prompt_auto))? state->prompt_auto: "";
}

R_IPI char *r2ai_auto_system_prompt(RCorePluginSession *cps) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	const char *base_system = r_config_get (core->config, "r2ai.system");
	const char *prompt_auto = auto_prompt_get (state);
	const char *think_prefix = r_config_get_b (core->config, "r2ai.auto.think")
		? ""
		: "/no_think\nReasoning: Low\n";
	return R_STR_ISNOTEMPTY (base_system)
		? r_str_newf ("%s%s\n\n%s", think_prefix, base_system, prompt_auto)
		: r_str_newf ("%s%s", think_prefix, prompt_auto);
}

// Helper function to process messages and handle tool calls recursively
R_API void process_messages(RCorePluginSession *cps, RList *messages, const char *system_prompt, int n_run) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	char *error = NULL;
	bool interrupted = false;
	const int max_runs = r_config_get_i (core->config, "r2ai.auto.max_runs");

	if (n_run > max_runs) {
		R_LOG_WARN ("Max runs reached");
		r_cons_flush (core->cons);
		return;
	}

	const char *effective_prompt = system_prompt? system_prompt: auto_prompt_get (state);
	if (!system_prompt) {
		const char *init_commands = r_config_get (core->config, "r2ai.auto.init_commands");
		if (R_STR_ISNOTEMPTY (init_commands)) {
			char *tool_args = r_str_newf ("{\"command\":\"%s\"}", init_commands);
			R2AI_ToolResult tool_result = execute_tool (cps, "r2cmd", tool_args);
			free (tool_args);
			if (R_STR_ISNOTEMPTY (tool_result.output)) {
				char *display_command = strip_command_comment (init_commands, NULL);
				char *content = r_str_newf ("Here is some information about the binary to get you started:\n>%s\n%s", display_command, tool_result.output);
				if (tool_result.comment && *tool_result.comment) {
					char *new_content = r_str_newf ("%s\nHINT: %s", content, tool_result.comment);
					free (content);
					content = new_content;
				}
				R2AI_Message init_msg = {
					.role = "system",
					.content = content
				};
				r2ai_msgs_add (messages, &init_msg);
				free (display_command);
			}
			r2ai_tool_result_fini (&tool_result);
		}
	}

	r2ai_stats_init_run (state, n_run);

	r_cons_printf (core->cons, Color_BLUE "About to call r2ai_llmcall with n_run=%d%s\n", n_run, Color_RESET);
	r_cons_flush (core->cons);

	// Set up args for r2ai_llmcall call with tools directly
	R2AIArgs args = {
		.messages = messages,
		.error = &error,
		.dorag = true,
		.tools = r2ai_get_tools (core, cps->data), // Always send tools in auto mode
		.system_prompt = effective_prompt
	};

	R2AI_ChatResponse *response = r2ai_llmcall (cps, args);
	if (!response) {
		R_LOG_ERROR ("No response from llmcall");
		handle_final_response_attempt (cps, messages, effective_prompt, &error);
		return;
	}

	const R2AI_Message *message = response->message;
	const R2AI_Usage *usage = response->usage;

	if (!message) {
		R_LOG_ERROR ("No message in response");
		free (response);
		handle_final_response_attempt (cps, messages, effective_prompt, &error);
		return;
	}

	// Debug logging for rawtools
	R_LOG_DEBUG ("Model response - Role: %s", message->role? message->role: "null");
	if (message->content) {
		R_LOG_DEBUG ("Content: %s", message->content);
	}
	if (message->reasoning_content) {
		R_LOG_DEBUG ("Reasoning: %s", message->reasoning_content);
	}
	if (message->tool_calls && r_list_length (message->tool_calls) > 0) {
		R_LOG_DEBUG ("Tool calls: %d", r_list_length (message->tool_calls));
		RListIter *iter;
		R2AI_ToolCall *tc;
		int i = 0;
		r_list_foreach (message->tool_calls, iter, tc) {
			R_LOG_DEBUG ("Tool %d: %s - %s", i, tc->name? tc->name: "null", tc->arguments? tc->arguments: "null");
			i++;
		}
	}

	// Process the response - we need to add it to our messages array
	if (message->content || message->reasoning_content) {
		r_cons_printf (core->cons, Color_RED "[Assistant]" Color_RESET);
		if (message->reasoning_content) {
			r_cons_printf (core->cons, Color_GRAY "<thinking>\n%s\n</thinking>" Color_RESET "\n", message->reasoning_content);
			r_cons_newline (core->cons);
			r_cons_flush (core->cons);
		}
		if (message->content) {
			r_cons_printf (core->cons, "%s", message->content);
			r_cons_newline (core->cons);
			r_cons_flush (core->cons);
		}
	}

	// Add the response to our messages array
	// This creates a copy, so we can safely free the original later
	r2ai_msgs_add (messages, message);

	// Check for tool calls and process them
	if (message->tool_calls && r_list_length (message->tool_calls) > 0) {
		R_LOG_DEBUG ("Found %d tool call(s)", r_list_length (message->tool_calls));

		// Process only the first tool call
		RListIter *iter;
		R2AI_ToolCall *tool_call;
		int i = 0;
		r_list_foreach (message->tool_calls, iter, tool_call) {

			if (!tool_call->name || !tool_call->arguments || !tool_call->id) {
				R_LOG_DEBUG ("Skipping invalid tool call %d", i);
				i++;
				continue;
			}
			R_LOG_DEBUG ("Processing first tool call %d: %s with args: %s", i, tool_call->name, tool_call->arguments);
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
			char *comment = NULL;
			if (interrupted) {
				cmd_output = strdup ("<user interrupted>");
			} else {
				R2AI_ToolResult tool_result = execute_tool (cps, tool_name, tool_args);
				cmd_output = tool_result.output;
				tool_result.output = NULL;
				comment = tool_result.comment;
				tool_result.comment = NULL;
				if (tool_result.edited_command) {
					// Update the last message's tool call arguments with the edited command
					R2AI_Message *last_msg = r_list_get_n (messages, r_list_length (messages) - 1);
					if (last_msg) {
						if (!strcmp (tool_name, "r2cmd")) {
							update_tool_call_argument (last_msg, tool_call->id, "command", tool_result.edited_command);
						} else if (!strcmp (tool_name, "execute_js")) {
							update_tool_call_argument (last_msg, tool_call->id, "script", tool_result.edited_command);
						}
					}
				}
				r2ai_tool_result_fini (&tool_result);
			}

			free (tool_name);
			free (tool_args);
			if (!cmd_output) {
				cmd_output = strdup ("<no output>");
			}
			if (strcmp (cmd_output, "R2AI_SIGINT") == 0) {
				r_cons_printf (core->cons, "\n\n\x1b[1" Color_RED "[r2ai] Processing interrupted after tool execution" Color_RESET "\n\n");
				r_cons_flush (core->cons);
				free (cmd_output);
				cmd_output = strdup ("<user interrupted>");
				interrupted = true;

				handle_final_response_attempt (cps, messages, effective_prompt, &error);
			}
			if (comment) {
				char *msg = r_str_newf ("HINT: %s\n%s", comment, cmd_output);
				free (cmd_output);
				cmd_output = msg;
			}
			free (comment);

			// Create a tool call response message
			R2AI_Message tool_response = {
				.role = "tool",
				.tool_call_id = strdup (tool_call->id),
				.content = cmd_output
			};

			// Add the tool response to our messages array
			r2ai_msgs_add (messages, &tool_response);
			R_LOG_DEBUG ("Added tool response to messages: %s", cmd_output? cmd_output: "null");
			r_cons_printf (core->cons, Color_GREEN "Tool result: %s" Color_RESET, cmd_output? cmd_output: "no output");
			free (cmd_output);
			i++;
#if 0
			// Only process the first valid tool call
			break;
#endif
		}

		r2ai_print_run_end (cps, usage, n_run, max_runs);

		// Check if we should continue with recursion
		if (!interrupted && message->tool_calls && r_list_length (message->tool_calls) > 0) {
			R_LOG_DEBUG ("Recursing to process_messages with n_run=%d", n_run + 1);
			process_messages (cps, messages, effective_prompt, n_run + 1);
		} else {
			R_LOG_DEBUG ("Auto mode loop ending - no more tool calls or interrupted");
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
	r_cons_printf (core->cons, Color_CYAN "cmd_r2ai_a called with query: %s" Color_RESET "\n", user_query);
	r_cons_flush (core->cons);
	// Get conversation
	RList *messages = r2ai_conversation_get (state);
	if (!messages) {
		R_LOG_ERROR ("Conversation not initialized");
		return;
	}

	// Add user query to the conversation (no system prompt)
	// If this is the first message in a new conversation, clear previous history
	if (r_list_empty (messages) || r_config_get_b (core->config, "r2ai.auto.reset_on_query")) {
		r2ai_msgs_clear (messages);
	}

	// Add user query
	R2AI_Message user_msg = {
		.role = "user",
		.content = (char *)user_query
	};
	r2ai_msgs_add (messages, &user_msg);

	char *system_prompt = r2ai_auto_system_prompt (cps);
	process_messages (cps, messages, system_prompt, 1);
	free (system_prompt);
}

// Helper function to display content with length indication for long content
static void print_content_with_length(RCore *core, const char *content, const char *empty_msg) {
	if (R_STR_ISEMPTY (content)) {
		r_cons_println (core->cons, empty_msg? empty_msg: "<no content>");
	} else {
		r_cons_println (core->cons, content);
	}
}

// Add this function right after cmd_r2ai_a
R_IPI void cmd_r2ai_logs(RCorePluginSession *cps, const char *flags) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	// Get conversation
	RList *messages = r2ai_conversation_get (state);
	if (!messages || r_list_empty (messages)) {
		r_cons_printf (core->cons, "No conversation history available\n");
		return;
	}

	bool json_mode = flags && strchr (flags, 'j');

	if (json_mode) {
		PJ *pj = pj_new ();
		if (!pj) {
			return;
		}

		pj_a (pj);

		RListIter *iter;
		const R2AI_Message *msg;
		r_list_foreach (messages, iter, msg) {
			pj_o (pj);
			pj_ks (pj, "role", msg->role? msg->role: "unknown");
			pj_ks (pj, "content", msg->content? msg->content: "");
			if (msg->tool_calls && r_list_length (msg->tool_calls) > 0) {
				pj_ka (pj, "tool_calls");
				RListIter *iter;
				R2AI_ToolCall *tc;
				r_list_foreach (msg->tool_calls, iter, tc) {
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
		r_cons_printf (core->cons, "%s\n", json_str);
		free (json_str);

		return;
	}

	r_cons_printf (core->cons, "\x1b[1" Color_BLUE "[r2ai] Chat Logs (%d messages)" Color_RESET "\n", r_list_length (messages));

	r_cons_printf (core->cons, "\x1b[1" Color_YELLOW "Note: System prompt is applied automatically but not stored in history" Color_RESET "\n\n");

	// Display each message in the conversation
	RListIter *iter;
	const R2AI_Message *msg;
	r_list_foreach (messages, iter, msg) {
		const char *role = msg->role;

		// Format based on role
		if (!strcmp (role, "user")) {
			r_cons_printf (core->cons, "\x1b[1" Color_GREEN "[user]:" Color_RESET " ");
			print_content_with_length (core, msg->content, "<no content>");
		} else if (!strcmp (role, "assistant")) {
			r_cons_printf (core->cons, "\x1b[1" Color_CYAN "[assistant]:" Color_RESET " ");
			print_content_with_length (core, msg->content, "<no content>");
			// Show tool calls if present
			if (msg->tool_calls && r_list_length (msg->tool_calls) > 0) {
				RListIter *iter;
				R2AI_ToolCall *tc;
				r_list_foreach (msg->tool_calls, iter, tc) {
					r_cons_printf (core->cons, "  \x1b[1" Color_MAGENTA "[tool call]:" Color_RESET " %s\n", tc->name? tc->name: "<unnamed>");

					if (tc->arguments) {
						r_cons_printf (core->cons, "    %s\n", tc->arguments);
					}
				}
			}
		} else if (!strcmp (role, "tool")) {
			r_cons_printf (core->cons, "\x1b[1" Color_MAGENTA "[tool]:" Color_RESET " ");
			print_content_with_length (core, msg->content, "<no result>");

			// Don't show the tool call ID as requested
		} else {
			// Other roles (system, etc.)
			r_cons_printf (core->cons, "\x1b[1" Color_WHITE "[%s]:" Color_RESET " ", role);
			print_content_with_length (core, msg->content, "<no content>");
		}

		r_cons_newline (core->cons);
		r_cons_flush (core->cons);
	}
}

// Helper function to format conversation log as string
static char *format_conversation_log(RList *messages) {
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, "Conversation Log:\n");

	RListIter *iter;
	const R2AI_Message *msg;
	r_list_foreach (messages, iter, msg) {
		const char *role = msg->role;

		if (!strcmp (role, "user")) {
			r_strbuf_appendf (sb, "[user]: %s\n", msg->content? msg->content: "<no content>");
		} else if (!strcmp (role, "assistant")) {
			r_strbuf_appendf (sb, "[assistant]: %s\n", msg->content? msg->content: "<no content>");
			// Include tool calls if present
			if (msg->tool_calls && r_list_length (msg->tool_calls) > 0) {
				RListIter *iter_tc;
				R2AI_ToolCall *tc;
				r_list_foreach (msg->tool_calls, iter_tc, tc) {
					r_strbuf_appendf (sb, "  [tool call]: %s\n", tc->name? tc->name: "<unnamed>");
					if (tc->arguments) {
						r_strbuf_appendf (sb, "    %s\n", tc->arguments);
					}
				}
			}
		} else if (!strcmp (role, "tool")) {
			r_strbuf_appendf (sb, "[tool]: %s\n", msg->content? msg->content: "<no result>");
		} else {
			r_strbuf_appendf (sb, "[%s]: %s\n", role, msg->content? msg->content: "<no content>");
		}
	}

	return r_strbuf_drain (sb);
}

// Helper function to process conversation with LLM and handle result
static void process_conversation_with_llm(RCorePluginSession *cps, bool compact) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	// Get conversation
	RList *messages = r2ai_conversation_get (state);
	if (!messages || r_list_empty (messages)) {
		r_cons_printf (core->cons, "No conversation history available\n");
		return;
	}

	// Format conversation as string
	char *log_str = format_conversation_log (messages);

	// Load the compact prompt from file
	char *prompt_text = r2ai_load_prompt_text (core, "compact");
	if (!prompt_text) {
		// Fallback to hardcoded prompt
		prompt_text = strdup (compact
				? "Create a compact summary of this conversation that preserves all key information, insights, and context for future reference."
					"Focus on essential details about the binary analysis, tools used, findings, and any important conclusions."
				: "mai create a summary of all the information retrieved from the binary that is relevant for future work");
	}

	// Combine log and prompt
	char *full_input = r_str_newf ("%s\n\n%s", log_str, prompt_text);

	char *error = NULL;
	char *res = r2ai (cps, (R2AIArgs){ .input = full_input, .error = &error, .dorag = false });

	free (log_str);
	free (full_input);
	free (prompt_text);

	if (error) {
		R_LOG_ERROR ("%s", error);
		free (error);
		return;
	}

	if (res) {
		if (compact) {
			// Clear the conversation and add summary as system message
			r2ai_msgs_clear (messages);
			R2AI_Message summary_msg = {
				.role = "system",
				.content = res
			};
			r2ai_msgs_add (messages, &summary_msg);
			r_cons_printf (core->cons, "Conversation compacted. Summary added to history.\n");
		} else {
			// Just print the result
			r_cons_printf (core->cons, "%s\n", res);
		}
		free (res);
	}
}

R_IPI void cmd_r2ai_c(RCorePluginSession *cps) {
	process_conversation_with_llm (cps, true);
}

R_IPI void cmd_r2ai_lr(RCorePluginSession *cps) {
	process_conversation_with_llm (cps, false);
}
