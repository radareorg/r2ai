#ifndef R2AI_H
#define R2AI_H

#include <r_core.h>
#include <r_util/r_json.h>
#include "r_vdb.h"
#include "markdown.h"

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
	const char *type;
	const char *id;
	const char *name;
	const char *input;
	const char *data;
	const char *thinking;
	const char *signature;
	const char *text;
} R2AI_ContentBlock;

typedef struct {
	R2AI_ContentBlock *blocks;
	int n_blocks;
} R2AI_ContentBlocks;

typedef struct {
	const char *role;
	const char *content;
	const R2AI_ContentBlocks *content_blocks;
	const char *tool_call_id;
	const R2AI_ToolCall *tool_calls;
	int n_tool_calls;
} R2AI_Message;

typedef struct {
	u_int64_t prompt_tokens;
	u_int64_t completion_tokens;
	u_int64_t total_tokens;
} R2AI_Usage;

typedef struct {
	const R2AI_Message *message;
	const R2AI_Usage *usage;
} R2AI_ChatResponse;

// Messages array management
typedef struct {
	R2AI_Message *messages;
	int n_messages;
	int cap_messages;
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

/**
 * Initialize a new empty messages array
 */
R_API R2AI_Messages *r2ai_msgs_new (void);

/**
 * Initialize the conversation container (call during plugin init)
 */
R_API void r2ai_conversation_init (void);

/**
 * Get the conversation instance (returns NULL if not initialized)
 */
R_API R2AI_Messages *r2ai_conversation_get (void);

/**
 * Clear all messages in a container without freeing the container
 */
R_API void r2ai_msgs_clear (R2AI_Messages *msgs);

/**
 * Add a message to the array
 * All strings are duplicated, so caller can free their copies
 */
R_API bool r2ai_msgs_add (R2AI_Messages *msgs, const R2AI_Message *msg);

/**
 * Add a tool call to the last message in the array
 * All strings are duplicated, so caller can free their copies
 */
R_API bool r2ai_msgs_add_tool_call (R2AI_Messages *msgs, const R2AI_ToolCall *tc);

/**
 * Parse a JSON response string and add the messages to the array
 * Returns true on success, false on failure
 */
R_API bool r2ai_msgs_from_response (R2AI_Messages *msgs, const char *json_str);

/**
 * Parse a RJson object directly and add the messages to the array
 * Returns true on success, false on failure
 */
R_API bool r2ai_msgs_from_json (R2AI_Messages *msgs, const RJson *json);

/**
 * Convert messages array to JSON string
 * Caller must free the returned string
 */
R_API char *r2ai_msgs_to_json (const R2AI_Messages *msgs);

/**
 * Convert messages array to Anthropic format JSON string
 * Caller must free the returned string
 */
R_API char *r2ai_msgs_to_anthropic_json (const R2AI_Messages *msgs);

/**
 * Free a messages array and all associated data
 */
R_API void r2ai_msgs_free (R2AI_Messages *msgs);

/**
 * Free the conversation (call during plugin unload)
 */
R_API void r2ai_conversation_free (void);

/**
 * Free a R2AI_Message structure
 */
R_API void r2ai_message_free (R2AI_Message *msg);

/**
 * Delete the last N messages from the message array
 * If n <= 0, defaults to deleting just the last message
 */
R_API void r2ai_delete_last_messages (R2AI_Messages *messages, int n);

/**
 * Get the global tools instance
 * Returns a pointer to the global tools structure
 */
R_API const R2AI_Tools *r2ai_get_tools (void);

/**
 * Parse OpenAI format tools JSON into internal tools structure
 * Caller must free the result with r2ai_tools_free
 */
R_API R2AI_Tools *r2ai_tools_parse (const char *tools_json);

/**
 * Convert tools structure to OpenAI format JSON
 * Caller must free the returned string
 */
R_API char *r2ai_tools_to_openai_json (const R2AI_Tools *tools);

/**
 * Convert tools structure to Anthropic format JSON
 * Caller must free the returned string
 */
R_API char *r2ai_tools_to_anthropic_json (const R2AI_Tools *tools);

/**
 * Free a tools structure and all associated data
 */
R_API void r2ai_tools_free (R2AI_Tools *tools);

/**
 * Execute a tool and return the output
 */
R_API char *execute_tool (RCore *core, const char *tool_name, const char *args);

/**
 * Send an HTTP POST request
 *
 * @param url The URL to send the request to
 * @param headers Array of headers, NULL terminated
 * @param data The data to send in the request
 * @param code Pointer to store the response code
 * @param rlen Pointer to store the response length
 * @return Response body as string (must be freed by caller) or NULL on error
 */
R_API char *r2ai_http_post (const char *url, const char *headers[], const char *data, int *code, int *rlen);

// anthropic
R_IPI R2AI_ChatResponse *r2ai_anthropic (RCore *core, R2AIArgs args);

// openai
R_IPI R2AI_ChatResponse *r2ai_openai (RCore *core, R2AIArgs args);
R_IPI void r2ai_openai_fini(void);

// auto mode
R_IPI void cmd_r2ai_a (RCore *core, const char *user_query);
R_IPI char *r2ai (RCore *core, R2AIArgs args);

R_IPI R2AI_ChatResponse *r2ai_llmcall (RCore *core, R2AIArgs args);

R_IPI void cmd_r2ai_logs (RCore *core);

/**
 * Create a conversation with system prompt and optional user message
 */
R_API R2AI_Messages *create_conversation (const char *system_prompt, const char *user_message);

/**
 * Process messages through LLM and handle tool calls recursively
 */
R_API void process_messages (RCore *core, R2AI_Messages *messages, const char *system_prompt, int n_run);

/**
 * Helper function to convert RJson to string
 */
R_API char *r_json_to_string(const RJson *json);

/**
 * Helper function to convert RJson to PJ
 */
R_API PJ *r_json_to_pj(const RJson *json, PJ *existing_pj);

#endif
