#include "r2ai.h"
#include <time.h>

// Forward declaration of the r2ai_llmcall function
extern R2AI_Message *r2ai_llmcall (RCore *core, R2AIArgs args);

// Add a global structure to track timing and costs
typedef struct {
	double total_cost;
	double run_cost;
	time_t start_time;
	time_t total_start_time;
} R2AIStats;

static R2AIStats stats = { 0 };

// Helper function to format time duration
static char *format_time_duration (time_t seconds) {
	if (seconds < 60) {
		return r_str_newf ("%llds", (long long)seconds);
	} else if (seconds < 3600) {
		return r_str_newf ("%lldm%llds", (long long)(seconds / 60), (long long)(seconds % 60));
	} else {
		return r_str_newf ("%lldh%lldm%llds",
			(long long)(seconds / 3600),
			(long long)((seconds % 3600) / 60),
			(long long)(seconds % 60));
	}
}

// Initialize timing and cost tracking for a run
static void r2ai_stats_init_run (int n_run) {
	time_t run_start = time (NULL);
	if (n_run == 1) {
		// First run, initialize total timing
		stats.total_cost = 0.0;
		stats.run_cost = 0.0;
		stats.total_start_time = run_start;
	}
	stats.start_time = run_start;
}

// Print a simple run indicator at the start
static void r2ai_print_run_end (RCore *core, int n_run, int max_runs) {
	time_t run_time = time (NULL) - stats.start_time;
	time_t total_time = time (NULL) - stats.total_start_time;

	// TODO: calculate cost
	stats.run_cost = 0.0 * run_time;
	stats.total_cost += stats.run_cost;

	// Format times for display
	char *run_time_str = format_time_duration (run_time);
	char *total_time_str = format_time_duration (total_time);

	// Print detailed stats
	r_cons_printf ("\x1b[1;34m%s | total: $%.10f | run: $%.10f | %d / %d | %s / %s\x1b[0m\n",
		r_config_get (core->config, "r2ai.model"),
		stats.total_cost,
		stats.run_cost,
		n_run, max_runs,
		run_time_str,
		total_time_str);
	r_cons_flush ();

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
static void process_messages (RCore *core, R2AI_Messages *messages, int n_run) {
	char *error = NULL;
	const int max_runs = r_config_get_i (core->config, "r2ai.auto.max_runs");
	if (n_run > max_runs) {
		r_cons_printf ("\x1b[1;31m[r2ai] Max runs reached\x1b[0m\n");
		r_cons_flush ();
		return;
	}

	r2ai_stats_init_run (n_run);

	const bool hide_tool_output = r_config_get_b (core->config, "r2ai.auto.hide_tool_output");
	const bool ask_to_execute = r_config_get_b (core->config, "r2ai.auto.ask_to_execute");
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
		r_cons_printf ("\x1b[1;32massistant:\x1b[0m\n%s\n", response->content);
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
				if (!hide_tool_output) {
					r_cons_printf ("%s", cmd_output);
					r_cons_flush ();
				}
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

		r2ai_print_run_end (core, n_run, max_runs);
		process_messages (core, messages, n_run + 1);
	} else {
		r2ai_print_run_end (core, n_run, max_runs);
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
	process_messages (core, messages, 1);

	// Free messages array
	r2ai_msgs_free (messages);
}
