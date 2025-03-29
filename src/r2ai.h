#ifndef R2AI_H
#define R2AI_H

#include <r_core.h>
#include <r_util/r_json.h>
#include "r_vdb.h"

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
	const char *role;
	const char *content;
	const char *tool_call_id;
	const R2AI_ToolCall *tool_calls;
	int n_tool_calls;
} R2AI_Message;

// Messages array management
typedef struct {
	R2AI_Message *messages;
	int n_messages;
	int cap_messages;
} R2AI_Messages;

typedef struct {
	const char *input;
	const char *model;
	const R2AI_Tools *tools; // Tools structure (replacing tools_json)
	R2AI_Messages *messages; // Array of message objects
	const char *provider;
	const char *api_key;
	bool dorag;
	char **error;
} R2AIArgs;

/**
 * Initialize a new empty messages array
 */
R_API R2AI_Messages *r2ai_msgs_new (void);

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
 * Free a R2AI_Message structure
 */
R_API void r2ai_message_free (R2AI_Message *msg);

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

// anthropic
R_IPI R2AI_Message *r2ai_anthropic (RCore *core, R2AIArgs args);
R_IPI char *r2ai_anthropic_stream (RCore *core, R2AIArgs args);
// openai
R_IPI R2AI_Message *r2ai_openai (RCore *core, R2AIArgs args);
R_IPI char *r2ai_openai_stream (RCore *core, R2AIArgs args);
// xai
R_IPI R2AI_Message *r2ai_xai (RCore *core, R2AIArgs args);
R_IPI char *r2ai_xai_stream (RCore *core, R2AIArgs args);
// openapi
R_IPI R2AI_Message *r2ai_openapi (RCore *core, R2AIArgs args);
R_IPI R2AI_Message *r2ai_ollama (RCore *core, R2AIArgs args);
// gemini
R_IPI R2AI_Message *r2ai_gemini (RCore *core, R2AIArgs args);
R_IPI char *r2ai_gemini_stream (RCore *core, R2AIArgs args);

// auto mode
R_IPI void cmd_r2ai_a (RCore *core, const char *user_query);
R_IPI char *r2ai (RCore *core, R2AIArgs args);

R_IPI R2AI_Message *r2ai_llmcall (RCore *core, R2AIArgs args);

#endif
