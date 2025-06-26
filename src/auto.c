#include "r2ai.h"
#include <time.h>

// Forward declaration of the r2ai_llmcall function
extern R2AI_ChatResponse *r2ai_llmcall(RCore *core, R2AIArgs args);

// Add a global structure to track timing and costs
typedef struct {
	double total_cost;
	double run_cost;
	int total_tokens;
	int run_tokens;
	int total_prompt_tokens;
	int run_prompt_tokens;
	int total_completion_tokens;
	int run_completion_tokens;
	time_t start_time;
	time_t total_start_time;
} R2AIStats;

static R2AIStats stats = { 0 };

// Helper function to format time duration
static char *format_time_duration(time_t seconds) {
	if (seconds < 60) {
		return r_str_newf ("%llds", (long long)seconds);
	}
	if (seconds < 3600) {
		return r_str_newf ("%lldm%llds", (long long)(seconds / 60), (long long)(seconds % 60));
	}
	return r_str_newf ("%lldh%lldm%llds",
			(long long)(seconds / 3600),
			(long long)((seconds % 3600) / 60),
			(long long)(seconds % 60));
}

// Initialize timing and cost tracking for a run
static void r2ai_stats_init_run(int n_run) {
	time_t run_start = time (NULL);
	if (n_run == 1) {
		// First run, initialize total timing
		stats.total_cost = 0.0;
		stats.run_cost = 0.0;
		stats.total_start_time = run_start;
		stats.total_tokens = 0;
		stats.run_tokens = 0;
		stats.total_prompt_tokens = 0;
		stats.run_prompt_tokens = 0;
		stats.total_completion_tokens = 0;
		stats.run_completion_tokens = 0;
	}
	stats.start_time = run_start;
}

// Print a simple run indicator at the start
static void r2ai_print_run_end(RCore *core, const R2AI_Usage *usage, int n_run, int max_runs) {
	time_t run_time = time (NULL) - stats.start_time;
	time_t total_time = time (NULL) - stats.total_start_time;
	if (usage) {
		stats.run_tokens = usage->total_tokens;
		stats.run_prompt_tokens = usage->prompt_tokens;
		stats.run_completion_tokens = usage->completion_tokens;
		stats.total_tokens += usage->total_tokens;
		stats.total_prompt_tokens += usage->prompt_tokens;
		stats.total_completion_tokens += usage->completion_tokens;
	}
	
	if (r_config_get_b (core->config, "r2ai.chat.show_cost") == true) {
		// TODO: calculate cost
		stats.run_cost = 0.0 * run_time;
		stats.total_cost += stats.run_cost;
	}

	// Format times for display
	char *run_time_str = format_time_duration (run_time);
	char *total_time_str = format_time_duration (total_time);

	// Print detailed stats
	R2_PRINTF ("\x1b[1;34m%s | total: %d in: %d out: %d | run: %d in: %d out: %d | %s / %s\x1b[0m\n",
		r_config_get (core->config, "r2ai.model"),
		stats.total_tokens,
		stats.total_prompt_tokens,
		stats.total_completion_tokens,
		stats.run_tokens,
		stats.run_prompt_tokens,
		stats.run_completion_tokens,
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
R_API void process_messages(RCore *core, R2AI_Messages *messages, const char *system_prompt, int n_run) {
	char *error = NULL;
	bool interrupted = false;
	const int max_runs = r_config_get_i (core->config, "r2ai.auto.max_runs");

	if (n_run > max_runs) {
		R2_PRINTF ("\x1b[1;31m[r2ai] Max runs reached\x1b[0m\n");
		R2_FLUSH ();
		return;
	}

	if (!system_prompt) {
		if (R_STR_ISNOTEMPTY (r_config_get (core->config, "r2ai.auto.init_commands"))) {
			const char *init_commands = r_config_get (core->config, "r2ai.auto.init_commands");
			if (init_commands) {
				char *edited_command = NULL;
				char *cmd_output = execute_tool (core, "r2cmd", r_str_newf ("{\"command\":\"%s\"}", init_commands), &edited_command);
				if (cmd_output) {
					system_prompt = r_str_newf ("%s\n\nHere is some information about the binary to get you started:\n>%s\n%s", Gprompt_auto, edited_command, cmd_output);
					free (cmd_output);
				}
				free (edited_command);
			}
		} else {
			system_prompt = Gprompt_auto;
		}
	}

	r2ai_stats_init_run (n_run);

	// Set up args for r2ai_llmcall call with tools directly
	R2AIArgs args = {
		.messages = messages,
		.error = &error,
		.dorag = true,
		.tools = r2ai_get_tools (),
		.system_prompt = system_prompt
	};

	// Call r2ai_llmcall to get a response
	R2AI_ChatResponse *response = r2ai_llmcall (core, args);

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
				continue;
			}
			R_LOG_DEBUG ("Tool call: %s", tool_call->name);
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
				// TODO: need to edit the R2AI_Messages* and modify the command of the last tool_use
				free(edited_command);
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
				.tool_call_id = tool_call->id,
				.content = cmd_output
			};

			// Add the tool response to our messages array
			r2ai_msgs_add (messages, &tool_response);
			free (cmd_output);
		}

		r2ai_print_run_end (core, usage, n_run, max_runs);

		// Check if we should continue with recursion
		if (!interrupted && message->tool_calls && message->n_tool_calls > 0) {
			process_messages (core, messages, system_prompt, n_run + 1);
		}
	} else {
		r2ai_print_run_end (core, usage, n_run, max_runs);
	}

	// Free the response struct itself since r2ai_message_free doesn't do it anymore
	free (response);
}

R_IPI void cmd_r2ai_a(RCore *core, const char *user_query) {
	// Get conversation
	R2AI_Messages *messages = r2ai_conversation_get ();
	if (!messages) {
		R_LOG_ERROR ("Conversation not initialized");
		return;
	}

	// Add user query to the conversation (no system prompt)
	// If this is the first message in a new conversation, clear previous history
	if (messages->n_messages == 0 || r_config_get_b (core->config, "r2ai.auto.reset_on_query")) {
		r2ai_msgs_clear (messages);
	}

	// Add user query
	R2AI_Message user_msg = {
		.role = "user",
		.content = user_query
	};
	r2ai_msgs_add (messages, &user_msg);

	process_messages (core, messages, NULL, 1);
}

// Helper function to display content with length indication for long content
static void print_content_with_length(RCore *core, const char *content, const char *empty_msg, bool always_show_length) {
	if (!content || *content == '\0') {
		R2_PRINTF ("%s\n", empty_msg ? empty_msg : "<no content>");
		return;
	}

	size_t content_len = strlen (content);
	const int max_display = 200;

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
R_IPI void cmd_r2ai_logs(RCore *core) {
	// Get conversation
	R2AI_Messages *messages = r2ai_conversation_get ();
	if (!messages || messages->n_messages == 0) {
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

		for (int i = 0; i < messages->n_messages; i++) {
			const R2AI_Message *msg = &messages->messages[i];

			pj_o (pj);

			pj_ks (pj, "role", msg->role ? msg->role : "unknown");
			pj_ks (pj, "content", msg->content ? msg->content : "");

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
		core->cons, messages->n_messages);

	R2_PRINTF ("\x1b[1;33mNote: System prompt is applied automatically but not stored in history\x1b[0m\n\n");

	// Display each message in the conversation
	for (int i = 0; i < messages->n_messages; i++) {
		const R2AI_Message *msg = &messages->messages[i];
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
						tc->name ? tc->name : "<unnamed>");

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
