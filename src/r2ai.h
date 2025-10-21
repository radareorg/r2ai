#ifndef R2AI_H
#define R2AI_H

#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <r_core.h>
#include <r_util/r_json.h>
#include "r_vdb.h"
#include "markdown.h"

#define R2AI_VERSION "1.1.2"
#define VDBDIM 16

#if R2_VERSION_NUMBER < 60000
#error Your radare2 is too old
#endif

// R_API definition if not available
#ifndef R_API
#define R_API
#endif

#ifndef R_IPI
#define R_IPI static
#endif

#define R2_PRINTF(...) r_cons_printf (core->cons, __VA_ARGS__)
#define R2_FLUSH() r_cons_flush (core->cons)
#define R2_NEWLINE() r_cons_newline (core->cons)
#define R2_PRINTLN(x) r_cons_println (core->cons, x)
#define R2_INTERRUPTED() r_cons_is_breaked (core->cons)

// Tool definition structure
typedef struct {
	char *name;
	char *description;
	char *parameters; // JSON string of parameters/input_schema
} R2AI_Tool;

// Tools array management
typedef struct {
	R2AI_Tool *tools;
	int n_tools;
} R2AI_Tools;

typedef struct {
	const char *name;
	const char *arguments;
	const char *id;
} R2AI_ToolCall;

typedef struct {
	char *type;
	char *id;
	char *name;
	char *input;
	char *data;
	char *thinking;
	char *signature;
	char *text;
} R2AI_ContentBlock;

typedef struct {
	R2AI_ContentBlock *blocks;
	int n_blocks;
} R2AI_ContentBlocks;

typedef struct {
	char *role;
	const char *content;
	char *reasoning_content;
	R2AI_ContentBlocks *content_blocks;
	char *tool_call_id;
	R2AI_ToolCall *tool_calls;
	int n_tool_calls;
} R2AI_Message;

typedef struct {
	char *title;
	char *author;
	char *desc;
	char *command;
	char *prompt;
	char *requires;
	char *if_empty;
	char *if_command;
} R2AIPrompt;

typedef struct {
	uint64_t prompt_tokens;
	uint64_t completion_tokens;
	uint64_t total_tokens;
} R2AI_Usage;

typedef struct {
	const R2AI_Message *message;
	const R2AI_Usage *usage;
} R2AI_ChatResponse;

// Messages array management
typedef struct {
	RList *messages; // RList<R2AI_Message *>
} R2AI_Messages;

typedef struct {
	const char *input;
	const char *model;
	const char *system_prompt; // System prompt to use
	const R2AI_Tools *tools; // Tools structure (replacing tools_json)
	R2AI_Messages *messages; // Array of message objects
	const char *provider;
	const char *api_key;
	int max_tokens;
	int thinking_tokens;
	float temperature;
	bool dorag;
	char **error;
} R2AIArgs;

// Stats structure from auto.c
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

// Main state structure to hold all global state
typedef struct r2ai_state_t {
	R2AI_Messages *conversation; // Global conversation messages (from messages.c)
	R2AIStats stats; // Global stats (from auto.c)
	R2AI_Tools *tools; // Global tools instance (from tools.c)
	RMarkdownTheme current_theme; // Global theme (from markdown.c)
	bool theme_initialized; // Global theme flag (from markdown.c)
	void *help_msg; // Global help message (from r2ai.c)
	RVdb *db; // Vector database for embeddings
	HtPP *model_compat_db; // Model compatibility database (from openai.c)
} R2AI_State;

/**
 * Initialize a new empty messages array
 */
R_API R2AI_Messages *r2ai_msgs_new(void);

/**
 * Initialize the conversation container (call during plugin init)
 */
R_API void r2ai_conversation_init(R2AI_State *state);

/**
 * Get the conversation instance (returns NULL if not initialized)
 */
R_API R2AI_Messages *r2ai_conversation_get(R2AI_State *state);

/**
 * Clear all messages in a container without freeing the container
 */
R_API void r2ai_msgs_clear(R2AI_Messages *msgs);

/**
 * Add a message to the array
 * All strings are duplicated, so caller can free their copies
 */
R_API bool r2ai_msgs_add(R2AI_Messages *msgs, const R2AI_Message *msg);

/**
 * Add a tool call to the last message in the array
 * All strings are duplicated, so caller can free their copies
 */
R_API bool r2ai_msgs_add_tool_call(R2AI_Messages *msgs, const R2AI_ToolCall *tc);

/**
 * Parse a JSON response string and add the messages to the array
 * Returns true on success, false on failure
 */
R_API bool r2ai_msgs_from_response(R2AI_Messages *msgs, const char *json_str);

/**
 * Parse a RJson object directly and add the messages to the array
 * Returns true on success, false on failure
 */
R_API bool r2ai_msgs_from_json(R2AI_Messages *msgs, const RJson *json);

/**
 * Convert messages array to JSON string
 * Caller must free the returned string
 */
R_API char *r2ai_msgs_to_json(const R2AI_Messages *msgs);

/**
 * Convert messages array to Anthropic format JSON string
 * Caller must free the returned string
 */
R_API char *r2ai_msgs_to_anthropic_json(const R2AI_Messages *msgs);

/**
 * Free a messages array and all associated data
 */
R_API void r2ai_msgs_free(R2AI_Messages *msgs);

/**
 * Free the conversation (call during plugin unload)
 */
R_API void r2ai_conversation_free(R2AI_State *state);

/**
 * Free a R2AI_Message structure
 */
R_API void r2ai_message_free(R2AI_Message *msg);

/**
 * Free a R2AIPrompt structure
 */
R_API void r2aiprompt_free(R2AIPrompt *prompt);

/**
 * Delete the last N messages from the message array
 * If n <= 0, defaults to deleting just the last message
 */
R_API void r2ai_delete_last_messages(R2AI_Messages *messages, int n);

/**
 * Get the global tools instance
 * Returns a pointer to the global tools structure
 */
R_API const R2AI_Tools *r2ai_get_tools(void);

/**
 * Parse OpenAI format tools JSON into internal tools structure
 * Caller must free the result with r2ai_tools_free
 */
R_API R2AI_Tools *r2ai_tools_parse(const char *tools_json);

/**
 * Convert tools structure to OpenAI format JSON
 * Caller must free the returned string
 */
R_API char *r2ai_tools_to_openai_json(const R2AI_Tools *tools);

/**
 * Convert tools structure to Anthropic format JSON
 * Caller must free the returned string
 */
R_API char *r2ai_tools_to_anthropic_json(const R2AI_Tools *tools);

/**
 * Free a tools structure and all associated data
 */
R_API void r2ai_tools_free(R2AI_Tools *tools);

/**
 * Execute a tool and return the output 
 * The command to execute is within args. The user may interactively
 * modify this command, hence edited_command contains the real
 * command which was run
 * Caller must free edited_command
 */
R_API char *execute_tool(RCore *core, const char *tool_name, const char *args, char **edited_command);

/**
 * Send an HTTP POST request
 *
 * @param core The RCore instance
 * @param url The URL to send the request to
 * @param headers Array of headers, NULL terminated
 * @param data The data to send in the request
 * @param code Pointer to store the response code
 * @param rlen Pointer to store the response length
 * @param use_files Use files instead of arguments
 * @return Response body as string (must be freed by caller) or NULL on error
 */
R_API char *r2ai_http_post(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen);

/**
 * Send an HTTP GET request
 *
 * @param url The URL to send the request to
 * @param headers Array of headers, NULL terminated
 * @param code Pointer to store the response code
 * @param rlen Pointer to store the response length
 * @return Response body as string (must be freed by caller) or NULL on error
 */
R_API char *r2ai_http_get(RCore *core, const char *url, const char *headers[], int *code, int *rlen);

/**
 * Get the base URL for a given provider
 *
 * @param core RCore instance for configuration
 * @param provider The provider name (e.g., "openai", "anthropic", etc.)
 * @return Base URL for the provider, or NULL if unknown
 */
R_IPI const char *r2ai_get_provider_url(RCore *core, const char *provider);

// anthropic
R_IPI R2AI_ChatResponse *r2ai_anthropic(RCorePluginSession *cps, R2AIArgs args);

// openai
R_IPI R2AI_ChatResponse *r2ai_openai(RCorePluginSession *cps, R2AIArgs args);
R_IPI void r2ai_openai_fini(R2AI_State *state);

// auto mode
R_IPI void cmd_r2ai_a(RCorePluginSession *cps, const char *user_query);
// R_API char *r2ai(RCore *core, R2AI_State *state, R2AIArgs args);
R_API char *r2ai(RCorePluginSession *cps, R2AIArgs args);
R_API bool r2ai_init(RCorePluginSession *cps);
R_API bool r2ai_fini(RCorePluginSession *cps);

R_IPI R2AI_ChatResponse *r2ai_llmcall(RCorePluginSession *cps, R2AIArgs args);

R_IPI void cmd_r2ai_logs(RCorePluginSession *cps);

/**
 * Create a conversation with system prompt and optional user message
 */
R_API R2AI_Messages *create_conversation(const char *user_message);

/**
 * Process messages through LLM and handle tool calls recursively
 */
R_API void process_messages(RCorePluginSession *cps, R2AI_Messages *messages, const char *system_prompt, int n_run);

/**
 * Helper function to convert RJson to string
 */
R_API char *r_json_to_string(const RJson *json);

/**
 * Helper function to convert RJson to PJ
 */
R_API PJ *r_json_to_pj(const RJson *json, PJ *existing_pj);

#endif
