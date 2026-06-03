#ifndef R2AI_H
#define R2AI_H

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <r_core.h>
#include <r_util/r_json.h>
#include <r_types_base.h>
#include "r_vdb.h"
#include "markdown.h"

#if R2_ABIVERSION < 83
#define r_core_call(x,y) r_core_cmd_call(x,y)
#endif

#define R2AI_VERSION "1.4.0"
#define R2AI_DEFAULT_MODEL "gpt-oss:20b"
#define R2AI_DEFAULT_PROVIDER "ollama"

#define R2AI_DEFAULT_VECTORS 16

// HTTP configuration structure
typedef struct {
	int timeout;
	int max_retries;
	int max_backoff;
} R2AI_HttpConfig;

// HTTP request structure
typedef struct {
	R2AI_HttpConfig config;
	const char *url;
	const char *data;
	const char **headers;
} HTTPRequest;

// HTTP response structure
typedef struct {
	char *body;
	int code;
	int length;
} HttpResponse;

#if R2_VERSION_NUMBER < 60000
#error Your radare2 is too old
#endif

// Tool definition structure
typedef struct {
	char *name;
	char *description;
	char *parameters; // JSON string of parameters/input_schema
} R2AI_Tool;

typedef struct {
	char *output;
	char *edited_command;
	char *comment;
} R2AI_ToolResult;

// Tools array management (now just RList<R2AI_Tool *>)

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

// Content blocks (now just RList<R2AI_ContentBlock *>)

/**
 * Create a new content blocks RList
 */
R_API RList *r2ai_content_blocks_new(void);

/**
 * Free a content blocks RList
 */
R_API void r2ai_content_blocks_free(RList *cb);

typedef struct {
	char *role;
	char *content;
	char *reasoning_content;
	RList *content_blocks; // RList<R2AI_ContentBlock *>
	char *tool_call_id;
	RList *tool_calls; // RList<R2AI_ToolCall *>
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
	char *model;
	char *provider;
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

// Messages array management (now just RList<R2AI_Message *>)

typedef struct {
	const char *input;
	const char *model;
	const char *system_prompt; // System prompt to use
	RList *tools; // Tools RList (replacing tools_json)
	RList *messages; // Array of message objects
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
	int total_tokens;
	int run_tokens;
	int total_prompt_tokens;
	int run_prompt_tokens;
	int total_completion_tokens;
	int run_completion_tokens;
	time_t start_time;
	time_t total_start_time;
} R2AIStats;

// Forward declaration for async task queue (defined in r2ai_priv.h)
struct r2ai_task_queue_t;

// Main state structure to hold all global state
typedef struct r2ai_state_t {
	RList *conversation; // Global conversation messages (from messages.c)
	R2AIStats stats; // Global stats (from auto.c)
	RList *tools; // Global tools instance (from tools.c)
	RMarkdown markdown; // Markdown rendering context
	void *help_msg; // Global help message (from r2ai.c)
	RVdb *db; // Vector database for embeddings
	struct r2ai_task_queue_t *async; // Async task queue (from async.c)
	char *prompt_auto; // Auto-mode system prompt
	char *vertex_token; // Cached Vertex AI OAuth2 token
	ut64 vertex_token_expiry; // Monotonic microseconds when the cached token expires
} R2AI_State;

// conversation
R_API void r2ai_conversation_init(R2AI_State *state);
R_API RList *r2ai_conversation_get(R2AI_State *state);
R_API void r2ai_conversation_free(R2AI_State *state);

// messages
R_API RList *r2ai_msgs_new(void);
R_API void r2ai_msgs_clear(RList *msgs);
R_API bool r2ai_msgs_add(RList *msgs, const R2AI_Message *msg);
R_API bool r2ai_msgs_add_tool_call(RList *msgs, const R2AI_ToolCall *tc);
R_API bool r2ai_msgs_from_response(RList *msgs, const char *json_str);
R_API bool r2ai_msgs_from_json(RList *msgs, const RJson *json);
R_API char *r2ai_msgs_to_json(const RList *msgs, bool raw_tool_args);
R_API char *r2ai_msgs_to_anthropic_json(const RList *msgs);
R_API void r2ai_msgs_free(RList *msgs);
R_API void r2ai_message_free(R2AI_Message *msg);
R_API void r2ai_message_fini(R2AI_Message *msg);
R_API void r2ai_delete_last_messages(RList *messages, int n);

// tools
R_API RList *r2ai_get_tools(RCore *core, R2AI_State *state);
R_API RList *r2ai_tools_parse(const char *tools_json);
R_API char *r2ai_tools_to_openai_json(const RList *tools);
R_API char *r2ai_tools_to_anthropic_json(const RList *tools);
R_API void r2ai_tools_free(RList *tools);
R_API void r2ai_tool_result_fini(R2AI_ToolResult *result);
R_API void r2ai_tool_call_free(R2AI_ToolCall *tc);
R_API R2AI_ToolResult execute_tool(RCorePluginSession *cps, const char *tool_name, const char *args);

/**
 * Execute r_core_cmd_str with slim mode if enabled
 * Temporarily sets asm.lines.fcn=false and scr.utf8=false if r2ai.auto.slim is true
 */
R_API char *r2ai_cmdstr(RCore *core, const char *cmd);

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
R_API char *r2ai_http_post(RCore *core, const char *url, const char **headers, const char *data, int *code, int *rlen);

/**
 * Send an HTTP GET request
 *
 * @param url The URL to send the request to
 * @param headers Array of headers, NULL terminated
 * @param code Pointer to store the response code
 * @param rlen Pointer to store the response length
 * @return Response body as string (must be freed by caller) or NULL on error
 */
R_API char *r2ai_http_get(RCore *core, const char *url, const char **headers, int *code, int *rlen);

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
R_IPI R2AI_ChatResponse *r2ai_anthropic_parse_response(const char *json, char **error);

// openai
R_IPI R2AI_ChatResponse *r2ai_openai(RCorePluginSession *cps, R2AIArgs args);

// gemini
R_IPI R2AI_ChatResponse *r2ai_gemini(RCorePluginSession *cps, R2AIArgs args);

// auto mode
R_IPI void cmd_r2ai_a(RCorePluginSession *cps, const char *user_query);
R_IPI char *r2ai_auto_system_prompt(RCorePluginSession *cps);
// R_API char *r2ai(RCore *core, R2AI_State *state, R2AIArgs args);
R_API char *r2ai(RCorePluginSession *cps, R2AIArgs args);
R_API bool r2ai_init(RCorePluginSession *cps);
R_API bool r2ai_fini(RCorePluginSession *cps);

R_IPI R2AI_ChatResponse *r2ai_llmcall(RCorePluginSession *cps, R2AIArgs args);

R2AI_ChatResponse *r2ai_rawtools_llmcall(RCorePluginSession *cps, R2AIArgs args);

R_IPI void cmd_r2ai_c(RCorePluginSession *cps);
R_IPI void cmd_r2ai_logs(RCorePluginSession *cps, const char *flags);
R_IPI void cmd_r2ai_lr(RCorePluginSession *cps);

/**
 * Process messages through LLM and handle tool calls recursively
 */
R_API void process_messages(RCorePluginSession *cps, RList *messages, const char *system_prompt, int n_run);

// json helpers that must be moved into r2
R_API char *r_json_to_string(const RJson *json);
R_API PJ *r_json_to_pj(const RJson *json, PJ *existing_pj);

// commands
R_API void r2ai_cmd_q(RCorePluginSession *cps, const char *input);
R_API void r2ai_cmd_qj(RCorePluginSession *cps, const char *input);
R_API char *find_prompt_file(RList *search_dirs, const char *name);
R_API R2AIPrompt *parse_prompt_file(const char *filepath);
R_API void r2aiprompt_free(R2AIPrompt *prompt);
R_API char *r2ai_load_prompt_text(RCore *core, const char *name);
R_API char *strip_command_comment(const char *input, char **comment_out);
R_API bool r2ai_wizard(RCore *core);
R_API bool r2ai_wizard_autorun(RCore *core);
R_API bool r2ai_wizard_isfirsttime(void);

#endif
