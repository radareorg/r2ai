#ifndef INCLUDE_R2AI_PRIV__H
#define INCLUDE_R2AI_PRIV__H

#include "r2ai.h"
#include <r_th.h>

typedef enum {
	R2AI_API_OPENAI_COMPATIBLE,
	R2AI_API_ANTHROPIC,
	R2AI_API_GEMINI,
	R2AI_API_OLLAMA,
	R2AI_API_VERTEX_GEMINI,
	R2AI_API_VERTEX_ANTHROPIC
} R2AI_API_Type;

/* Async task subsystem (see ASYNC.md) */
typedef enum {
	R2AI_TASK_PENDING = 0,
	R2AI_TASK_RUNNING,
	R2AI_TASK_WAIT_APPROVE,
	R2AI_TASK_WAIT_INPUT,
	R2AI_TASK_COMPLETE,
	R2AI_TASK_ERROR,
	R2AI_TASK_CANCELLED,
} R2AITaskState;

typedef enum {
	R2AI_TASK_QUERY = 0,
	R2AI_TASK_AUTO,
} R2AITaskKind;

typedef struct r2ai_task_t {
	int id;
	R2AITaskKind kind;
	R2AITaskState state;
	char *title;
	char *query;
	char *system_prompt;
	char *model;
	char *provider;
	RList *messages; /* R2AI_Message * - owned conversation */
	RStrBuf *output; /* flushed by -si */
	char *error;
	char *pending_tool_name;
	char *pending_tool_args;
	char *pending_tool_call_id;
	char *tool_result; /* main -> worker handoff */
	bool flushed; /* output already printed */
	bool cancel_req;
	RThread *thread;
	RThreadLock *lock;
	RThreadSemaphore *gate;
	RCorePluginSession *cps;
	time_t created;
	time_t started;
	time_t finished;
	int steps;
} R2AITask;

typedef struct r2ai_task_queue_t {
	RList *tasks;
	RThreadLock *lock;
	int next_id;
} R2AITaskQueue;

R_IPI void r2ai_async_init(R2AI_State *state);
R_IPI void r2ai_async_fini(R2AI_State *state);
R_IPI int r2ai_async_query(RCorePluginSession *cps,
	const char *title, const char *query, const char *sysp);
R_IPI int r2ai_async_auto(RCorePluginSession *cps,
	const char *title, const char *query, const char *sysp);
R_IPI void r2ai_async_cmd(RCorePluginSession *cps, const char *input);

typedef struct {
	const char *name;
	const char *url;
	R2AI_API_Type api_type;
	bool requires_api_key;
	bool supports_custom_baseurl;
} R2AIProvider;

R_API void cmd_r2ai(RCorePluginSession *cps, const char *input);
R_IPI const R2AIProvider *r2ai_get_provider(const char *name);
R_IPI const char *r2ai_get_provider_url(RCore *core, const char *provider);
R_IPI RList *r2ai_fetch_available_models(RCore *core, const char *provider);
R_IPI void r2ai_list_providers(RCore *core, RStrBuf *sb);
R_IPI void r2ai_refresh_embeddings(RCorePluginSession *cps);
R_API char *r2ai_apikeys_path(bool *exists);
R_API void r2ai_apikeys_edit(RCorePluginSession *cps);
R_API char *r2ai_apikeys_get(const char *provider);

/* vertex.c */
R_IPI const char *r2ai_vertex_get_token(R2AI_State *state);
R_IPI R2AI_ChatResponse *r2ai_vertex_gemini(RCorePluginSession *cps, R2AIArgs args);
R_IPI R2AI_ChatResponse *r2ai_vertex_anthropic(RCorePluginSession *cps, R2AIArgs args);

/* claw.c - SOUL.md / IDENTITY.md personality files */
#define R2AI_CLAW_HINT "use 'r2ai -ide' to edit or 'r2ai -id-' to delete"
R_API bool r2ai_claw_exists(void);
R_API char *r2ai_claw_system_prompt(const char *base);
R_API void r2ai_claw_create(RCorePluginSession *cps, const char *user_extra);
R_API void r2ai_claw_show(RCorePluginSession *cps);
R_API void r2ai_claw_edit(RCorePluginSession *cps);
R_API void r2ai_claw_delete(RCorePluginSession *cps);

#endif
