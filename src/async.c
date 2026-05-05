/* Copyright r2ai - 2023-2026 - pancake */

#define R_LOG_ORIGIN "r2ai.async"

#include "r2ai.h"
#include "r2ai_priv.h"
#include <r_th.h>

static const char *state_name(R2AITaskState s) {
	switch (s) {
	case R2AI_TASK_PENDING: return "pending";
	case R2AI_TASK_RUNNING: return "running";
	case R2AI_TASK_WAIT_APPROVE: return "wait-approve";
	case R2AI_TASK_WAIT_INPUT: return "wait-input";
	case R2AI_TASK_COMPLETE: return "complete";
	case R2AI_TASK_ERROR: return "error";
	case R2AI_TASK_CANCELLED: return "cancelled";
	}
	return "?";
}

static const char *kind_name(R2AITaskKind k) {
	return k == R2AI_TASK_AUTO? "auto": "query";
}

static void task_lock(R2AITask *t) {
	r_th_lock_enter (t->lock);
}
static void task_unlock(R2AITask *t) {
	r_th_lock_leave (t->lock);
}

static bool task_is_live_locked(const R2AITask *t) {
	R2AITaskState s = t->state;
	return s == R2AI_TASK_PENDING || s == R2AI_TASK_RUNNING || s == R2AI_TASK_WAIT_APPROVE || s == R2AI_TASK_WAIT_INPUT;
}

/* Append text to task->output. Takes task lock. */
static void task_append_output(R2AITask *t, const char *text) {
	if (R_STR_ISEMPTY (text)) {
		return;
	}
	task_lock (t);
	r_strbuf_append (t->output, text);
	task_unlock (t);
}

static void task_append_outputf(R2AITask *t, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	char *s = r_str_newvf (fmt, ap);
	va_end (ap);
	task_append_output (t, s);
	free (s);
}

static void task_free(R2AITask *t) {
	if (!t) {
		return;
	}
	if (t->thread) {
		r_th_wait (t->thread);
		r_th_free (t->thread);
	}
	if (t->gate) {
		r_th_sem_free (t->gate);
	}
	if (t->lock) {
		r_th_lock_free (t->lock);
	}
	if (t->messages) {
		r2ai_msgs_free (t->messages);
	}
	free (t->title);
	free (t->query);
	free (t->system_prompt);
	free (t->model);
	free (t->provider);
	r_strbuf_free (t->output);
	free (t->error);
	free (t->pending_tool_name);
	free (t->pending_tool_args);
	free (t->pending_tool_call_id);
	free (t->tool_result);
	free (t);
}

static void queue_lock(R2AITaskQueue *q) {
	r_th_lock_enter (q->lock);
}
static void queue_unlock(R2AITaskQueue *q) {
	r_th_lock_leave (q->lock);
}

/* Build the LLM args for the worker, without any live RCore work. */
static void fill_args_from_task(R2AITask *t, R2AIArgs *args, char **error) {
	memset (args, 0, sizeof (*args));
	args->messages = t->messages;
	args->system_prompt = t->system_prompt;
	args->model = t->model;
	args->provider = t->provider;
	args->error = error;
	args->dorag = false;
}

/* Worker: execute one LLM turn, appending any text output.
 * Returns the R2AI_ChatResponse (caller owns). */
static R2AI_ChatResponse *run_llm_once(R2AITask *t) {
	char *error = NULL;
	R2AIArgs args;
	fill_args_from_task (t, &args, &error);

	/* For AUTO tasks we must send tools. */
	if (t->kind == R2AI_TASK_AUTO) {
		args.tools = r2ai_get_tools (t->cps->core, t->cps->data);
	}

	R2AI_ChatResponse *res = r2ai_llmcall (t->cps, args);

	if (error) {
		task_lock (t);
		free (t->error);
		t->error = error;
		task_unlock (t);
	}
	return res;
}

/* Append human-readable chunks of the assistant message to task output. */
static void dump_message_to_output(R2AITask *t, const R2AI_Message *m) {
	if (!m) {
		return;
	}
	if (m->reasoning_content) {
		task_append_outputf (t, "<thinking>\n%s\n</thinking>\n", m->reasoning_content);
	}
	if (m->content) {
		task_append_outputf (t, "%s\n", m->content);
	}
}

/* Thread entry-point for QUERY tasks. */
static RThreadFunctionRet worker_query(RThread *th) {
	R2AITask *t = (R2AITask *)th->user;
	task_lock (t);
	t->state = R2AI_TASK_RUNNING;
	t->started = time (NULL);
	task_unlock (t);

	R2AI_ChatResponse *res = run_llm_once (t);
	task_lock (t);
	if (t->cancel_req) {
		t->state = R2AI_TASK_CANCELLED;
	} else if (!res || !res->message) {
		if (!t->error) {
			t->error = strdup ("llm call returned no response");
		}
		t->state = R2AI_TASK_ERROR;
	} else {
		const R2AI_Message *m = res->message;
		task_unlock (t);
		dump_message_to_output (t, m);
		task_lock (t);
		t->state = R2AI_TASK_COMPLETE;
	}
	t->finished = time (NULL);
	task_unlock (t);

	if (res) {
		r2ai_message_free ((R2AI_Message *)res->message);
		free (res);
	}
	return R_TH_STOP;
}

/* Thread entry-point for AUTO tasks. */
static RThreadFunctionRet worker_auto(RThread *th) {
	R2AITask *t = (R2AITask *)th->user;
	task_lock (t);
	t->state = R2AI_TASK_RUNNING;
	t->started = time (NULL);
	int max_runs = r_config_get_i (t->cps->core->config, "r2ai.auto.max_runs");
	task_unlock (t);

	while (true) {
		task_lock (t);
		if (t->cancel_req) {
			t->state = R2AI_TASK_CANCELLED;
			t->finished = time (NULL);
			task_unlock (t);
			return R_TH_STOP;
		}
		if (t->steps >= max_runs) {
			t->state = R2AI_TASK_ERROR;
			free (t->error);
			t->error = r_str_newf ("max runs (%d) reached", max_runs);
			t->finished = time (NULL);
			task_unlock (t);
			return R_TH_STOP;
		}
		t->steps++;
		t->state = R2AI_TASK_RUNNING;
		task_unlock (t);

		R2AI_ChatResponse *res = run_llm_once (t);
		if (!res || !res->message) {
			task_lock (t);
			if (!t->error) {
				t->error = strdup ("llm call returned no response");
			}
			t->state = R2AI_TASK_ERROR;
			t->finished = time (NULL);
			task_unlock (t);
			if (res) {
				free (res);
			}
			return R_TH_STOP;
		}
		const R2AI_Message *m = res->message;
		dump_message_to_output (t, m);
		r2ai_msgs_add (t->messages, m);

		bool has_tool = m->tool_calls && r_list_length (m->tool_calls) > 0;
		if (!has_tool) {
			task_lock (t);
			t->state = R2AI_TASK_COMPLETE;
			t->finished = time (NULL);
			task_unlock (t);
			r2ai_message_free ((R2AI_Message *)m);
			free (res);
			return R_TH_STOP;
		}

		/* Take the first valid tool call. */
		RListIter *iter;
		R2AI_ToolCall *tc, *valid_tc = NULL;
		r_list_foreach (m->tool_calls, iter, tc) {
			if (tc->name && tc->arguments && tc->id) {
				valid_tc = tc;
				break;
			}
		}
		if (!valid_tc) {
			task_lock (t);
			t->state = R2AI_TASK_ERROR;
			free (t->error);
			t->error = strdup ("llm returned an invalid tool call");
			t->finished = time (NULL);
			task_unlock (t);
			r2ai_message_free ((R2AI_Message *)m);
			free (res);
			return R_TH_STOP;
		}
		tc = valid_tc;
		char *name = tc->name? strdup (tc->name): NULL;
		char *argsjson = tc->arguments? strdup (tc->arguments): NULL;
		char *callid = tc->id? strdup (tc->id): NULL;
		r2ai_message_free ((R2AI_Message *)m);
		free (res);

		task_lock (t);
		free (t->pending_tool_name);
		free (t->pending_tool_args);
		free (t->pending_tool_call_id);
		free (t->tool_result);
		t->pending_tool_name = name;
		t->pending_tool_args = argsjson;
		t->pending_tool_call_id = callid;
		t->tool_result = NULL;
		t->state = R2AI_TASK_WAIT_APPROVE;
		task_unlock (t);

		/* Wait for main thread to provide tool_result via gate. */
		r_th_sem_wait (t->gate);

		task_lock (t);
		if (t->cancel_req) {
			t->state = R2AI_TASK_CANCELLED;
			t->finished = time (NULL);
			task_unlock (t);
			return R_TH_STOP;
		}
		char *tool_out = t->tool_result? t->tool_result: strdup ("<no output>");
		t->tool_result = NULL;
		char *tool_id = t->pending_tool_call_id? strdup (t->pending_tool_call_id): NULL;
		free (t->pending_tool_name);
		free (t->pending_tool_args);
		free (t->pending_tool_call_id);
		t->pending_tool_name = NULL;
		t->pending_tool_args = NULL;
		t->pending_tool_call_id = NULL;
		task_unlock (t);

		R2AI_Message tool_msg = {
			.role = "tool",
			.tool_call_id = tool_id,
			.content = tool_out,
};
		r2ai_msgs_add (t->messages, &tool_msg);
		free (tool_id);
		free (tool_out);
	}
	return R_TH_STOP;
}

R_IPI void r2ai_async_init(R2AI_State *state) {
	if (!state || state->async) {
		return;
	}
	R2AITaskQueue *q = R_NEW0 (R2AITaskQueue);
	q->tasks = r_list_newf ((RListFree)task_free);
	q->lock = r_th_lock_new (true);
	q->next_id = 1;
	state->async = q;
}

R_IPI void r2ai_async_fini(R2AI_State *state) {
	if (!state || !state->async) {
		return;
	}
	R2AITaskQueue *q = state->async;
	int killed = 0;
	/* Force-kill any live workers so we don't block on inflight HTTP. */
	queue_lock (q);
	RListIter *it;
	R2AITask *t;
	r_list_foreach (q->tasks, it, t) {
		task_lock (t);
		bool live = task_is_live_locked (t);
		t->cancel_req = true;
		task_unlock (t);
		if (t->gate) {
			r_th_sem_post (t->gate);
		}
		if (live && t->thread) {
			r_th_kill_free (t->thread);
			t->thread = NULL;
			killed++;
		}
	}
	queue_unlock (q);
	if (killed > 0) {
		R_LOG_INFO ("killed %d pending async task%s", killed, killed == 1? "": "s");
	}
	r_list_free (q->tasks);
	r_th_lock_free (q->lock);
	free (q);
	state->async = NULL;
}

static R2AITask *task_new(RCorePluginSession *cps, R2AITaskKind kind, const char *title, const char *query, const char *system_prompt) {
	RCore *core = cps->core;
	R2AITask *t = R_NEW0 (R2AITask);
	t->cps = cps;
	t->kind = kind;
	t->state = R2AI_TASK_PENDING;
	t->title = strdup (title? title: "");
	t->query = strdup (query? query: "");
	if (R_STR_ISEMPTY (system_prompt) && kind == R2AI_TASK_AUTO) {
		t->system_prompt = r2ai_auto_system_prompt (cps);
	} else {
		t->system_prompt = system_prompt? strdup (system_prompt): NULL;
	}
	const char *m = r_config_get (core->config, "r2ai.model");
	const char *p = r_config_get (core->config, "r2ai.api");
	t->model = m? strdup (m): NULL;
	t->provider = p? strdup (p): NULL;
	t->messages = r2ai_msgs_new ();
	R2AI_Message um = { .role = "user", .content = (char *)query };
	r2ai_msgs_add (t->messages, &um);
	t->lock = r_th_lock_new (false);
	t->gate = r_th_sem_new (0);
	t->output = r_strbuf_new (NULL);
	t->created = time (NULL);
	return t;
}

static int queue_register(R2AITaskQueue *q, R2AITask *t) {
	queue_lock (q);
	t->id = q->next_id++;
	r_list_append (q->tasks, t);
	queue_unlock (q);
	return t->id;
}

static int submit(RCorePluginSession *cps, R2AITaskKind kind, const char *title, const char *query, const char *sysp, RThreadFunction fn) {
	R2AI_State *state = cps->data;
	if (!state || !state->async) {
		return -1;
	}
	R2AITask *t = task_new (cps, kind, title, query, sysp);
	int id = queue_register (state->async, t);
	t->thread = r_th_new (fn, t, 0);
	if (t->thread) {
		r_th_start (t->thread);
	} else {
		task_lock (t);
		t->state = R2AI_TASK_ERROR;
		free (t->error);
		t->error = strdup ("failed to spawn worker");
		task_unlock (t);
	}
	return id;
}

R_IPI int r2ai_async_query(RCorePluginSession *cps,
	const char *title,
	const char *query,
	const char *sysp) {
	return submit (cps, R2AI_TASK_QUERY, title, query, sysp, worker_query);
}

R_IPI int r2ai_async_auto(RCorePluginSession *cps,
	const char *title,
	const char *query,
	const char *sysp) {
	return submit (cps, R2AI_TASK_AUTO, title, query, sysp, worker_auto);
}

static void purge_finished(RCorePluginSession *cps);

static void show_task_list(RCorePluginSession *cps, bool json) {
	R2AI_State *state = cps->data;
	RCore *core = cps->core;
	if (!state || !state->async) {
		r_cons_printf (core->cons, "async queue not initialised\n");
		return;
	}
	R2AITaskQueue *q = state->async;
	queue_lock (q);
	if (json) {
		PJ *pj = r_core_pj_new (cps->core);
		pj_o (pj);
		pj_ka (pj, "tasks");
		RListIter *it;
		R2AITask *t;
		r_list_foreach (q->tasks, it, t) {
			task_lock (t);
			pj_o (pj);
			pj_ki (pj, "id", t->id);
			pj_ks (pj, "kind", kind_name (t->kind));
			pj_ks (pj, "state", state_name (t->state));
			pj_ks (pj, "title", t->title? t->title: "");
			pj_ki (pj, "steps", t->steps);
			pj_ki (pj, "age", (int) (time (NULL) - t->created));
			if (t->pending_tool_name) {
				pj_ks (pj, "pending_tool", t->pending_tool_name);
			}
			if (t->pending_tool_args) {
				pj_ks (pj, "pending_tool_args", t->pending_tool_args);
			}
			if (t->pending_tool_call_id) {
				pj_ks (pj, "pending_tool_call_id", t->pending_tool_call_id);
			}
			const char *out = r_strbuf_get (t->output);
			if (R_STR_ISNOTEMPTY (out)) {
				pj_ks (pj, "output", out);
			}
			if (t->error) {
				pj_ks (pj, "error", t->error);
			}
			pj_end (pj);
			task_unlock (t);
		}
		pj_end (pj);
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_println (core->cons, s);
		free (s);
	} else if (r_list_empty (q->tasks)) {
		r_cons_printf (core->cons, "No async tasks\n");
	} else {
		r_cons_printf (core->cons, "%-4s %-6s %-13s %-4s  %s\n", "id", "kind", "state", "age", "title");
		RListIter *it;
		R2AITask *t;
		r_list_foreach (q->tasks, it, t) {
			task_lock (t);
			int age = (int) (time (NULL) - t->created);
			const char *extra = "";
			char *extrabuf = NULL;
			if (t->state == R2AI_TASK_WAIT_APPROVE && t->pending_tool_name) {
				extrabuf = r_str_newf (" [awaiting tool: %s]", t->pending_tool_name);
				extra = extrabuf;
			} else if (t->state == R2AI_TASK_ERROR && t->error) {
				extrabuf = r_str_newf (" [err: %s]", t->error);
				extra = extrabuf;
			}
			r_cons_printf (core->cons, "%-4d %-6s %-13s %-4d  %s%s\n", t->id, kind_name (t->kind), state_name (t->state), age, t->title? t->title: "", extra);
			const char *out = r_strbuf_get (t->output);
			if (R_STR_ISNOTEMPTY (out)) {
				r_cons_printf (core->cons, "output:\n%s", out);
				if (!r_str_endswith (out, "\n")) {
					r_cons_newline (core->cons);
				}
			}
			free (extrabuf);
			task_unlock (t);
		}
	}
	if (r_config_get_b (core->config, "r2ai.async.purge")) {
		purge_finished (cps);
	}
	queue_unlock (q);
}

static bool task_is_actionable_locked(const R2AITask *t) {
	switch (t->state) {
	case R2AI_TASK_COMPLETE:
	case R2AI_TASK_ERROR:
	case R2AI_TASK_WAIT_APPROVE:
	case R2AI_TASK_WAIT_INPUT:
		return true;
	default:
		return false;
	}
}

/* Find first actionable task (id == 0) or the task with the given id if
 * actionable. Returns with queue lock held; caller must release via
 * queue_unlock. Returns NULL if none found (lock released). */
static R2AITask *find_actionable(R2AITaskQueue *q, int id) {
	queue_lock (q);
	RListIter *it;
	R2AITask *t;
	r_list_foreach (q->tasks, it, t) {
		if (id > 0 && t->id != id) {
			continue;
		}
		task_lock (t);
		bool actionable = task_is_actionable_locked (t);
		task_unlock (t);
		if (actionable) {
			return t;
		}
	}
	queue_unlock (q);
	return NULL;
}

static void task_unlink_disk(const R2AITask *t) {
	char *path = r_file_homef (".config/r2ai/tasks/%d.json", t->id);
	if (path) {
		r_file_rm (path);
		free (path);
	}
}

static void drop_task_locked(R2AITaskQueue *q, R2AITask *t) {
	task_unlink_disk (t);
	r_list_delete_data (q->tasks, t);
}

static bool answer_wait_approve(RCorePluginSession *cps, R2AITask *t, bool approve, bool interactive) {
	RCore *core = cps->core;
	task_lock (t);
	if (t->state != R2AI_TASK_WAIT_APPROVE) {
		task_unlock (t);
		return false;
	}
	char *tool_name = t->pending_tool_name? strdup (t->pending_tool_name): NULL;
	char *tool_args = t->pending_tool_args? strdup (t->pending_tool_args): NULL;
	task_unlock (t);

	char *tool_output = NULL;
	if (approve) {
		bool old_yolo = r_config_get_b (core->config, "r2ai.auto.yolo");
		r_config_set_b (core->config, "r2ai.auto.yolo", true);
		R2AI_ToolResult tool_result = execute_tool (cps, tool_name, tool_args);
		r_config_set_b (core->config, "r2ai.auto.yolo", old_yolo);
		tool_output = tool_result.output;
		tool_result.output = NULL;
		r2ai_tool_result_fini (&tool_result);
		if (!tool_output) {
			tool_output = strdup ("<no output>");
		}
		task_append_outputf (t, "\nTool result (%s):\n%s\n", tool_name? tool_name: "?", tool_output);
		if (interactive) {
			r_cons_printf (core->cons, Color_GREEN "tool result:" Color_RESET " %s\n", tool_output);
		}
	} else {
		tool_output = strdup ("<user declined to run tool>");
		if (interactive) {
			r_cons_printf (core->cons, "declined.\n");
		} else {
			task_append_output (t, "\nTool declined by user.\n");
		}
	}

	task_lock (t);
	free (t->tool_result);
	t->tool_result = tool_output;
	t->state = R2AI_TASK_RUNNING;
	task_unlock (t);
	r_th_sem_post (t->gate);

	free (tool_name);
	free (tool_args);
	return true;
}

/* Interactive handler: act on first actionable task (or the given id). */
static void interact_once(RCorePluginSession *cps, int id) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	if (!state || !state->async) {
		return;
	}
	R2AITaskQueue *q = state->async;
	R2AITask *t = find_actionable (q, id);
	if (!t) {
		/* Nothing to do - silent by default so cmd.prompt stays clean. */
		return;
	}
	/* queue lock still held */
	task_lock (t);
	R2AITaskState st = t->state;
	int tid = t->id;
	char *output = r_strbuf_drain_nofree (t->output);
	char *err = t->error;
	t->error = NULL;
	char *tool_name = t->pending_tool_name? strdup (t->pending_tool_name): NULL;
	char *tool_args = t->pending_tool_args? strdup (t->pending_tool_args): NULL;
	R2AITaskKind kind = t->kind;
	task_unlock (t);
	queue_unlock (q);

	r_cons_printf (core->cons, "\n" Color_BLUE "[async task %d | %s | %s]" Color_RESET "\n", tid, kind_name (kind), state_name (st));
	if (!R_STR_ISEMPTY (output)) {
		r_cons_printf (core->cons, "%s", output);
		if (!r_str_endswith (output, "\n")) {
			r_cons_newline (core->cons);
		}
	}
	free (output);
	if (err) {
		r_cons_printf (core->cons, Color_RED "error: %s" Color_RESET "\n", err);
		free (err);
	}

	if (st == R2AI_TASK_COMPLETE || st == R2AI_TASK_ERROR || st == R2AI_TASK_CANCELLED) {
		/* Remove the task from the queue (join the thread on free). */
		queue_lock (q);
		drop_task_locked (q, t);
		queue_unlock (q);
		free (tool_name);
		free (tool_args);
		return;
	}

	if (st == R2AI_TASK_WAIT_APPROVE) {
		r_cons_printf (core->cons, Color_YELLOW "pending tool:" Color_RESET " %s\n", tool_name? tool_name: "?");
		if (tool_args) {
			r_cons_printf (core->cons, "args: %s\n", tool_args);
		}
		r_cons_flush (core->cons);

		bool yolo = r_config_get_b (core->config, "r2ai.auto.yolo");
		char *question = r_str_newf ("Run tool %s? (Y/n)", tool_name? tool_name: "?");
		bool approve = yolo? true: r_cons_yesno (core->cons, 'y', "%s", question? question: "Run tool? (Y/n)");
		free (question);
		answer_wait_approve (cps, t, approve, true);
	}
	free (tool_name);
	free (tool_args);
}

static R2AITask *find_by_id(R2AITaskQueue *q, int id) {
	RListIter *it;
	R2AITask *t;
	r_list_foreach (q->tasks, it, t) {
		if (t->id == id) {
			return t;
		}
	}
	return NULL;
}

static void answer_by_id(RCorePluginSession *cps, int id, bool approve) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	if (!state || !state->async) {
		return;
	}
	if (id <= 0) {
		r_cons_printf (core->cons, "Missing task id\n");
		return;
	}
	R2AITaskQueue *q = state->async;
	queue_lock (q);
	R2AITask *t = find_by_id (q, id);
	if (!t) {
		queue_unlock (q);
		r_cons_printf (core->cons, "No task with id %d\n", id);
		return;
	}
	task_lock (t);
	bool wait_approve = t->state == R2AI_TASK_WAIT_APPROVE;
	task_unlock (t);
	queue_unlock (q);

	if (!wait_approve) {
		r_cons_printf (core->cons, "Task %d is not waiting for approval\n", id);
		return;
	}
	if (answer_wait_approve (cps, t, approve, false)) {
		r_cons_printf (core->cons, "%s task %d\n", approve? "Approved": "Declined", id);
	}
}

static void kill_task_locked(R2AITaskQueue *q, R2AITask *t) {
	task_lock (t);
	t->cancel_req = true;
	bool live = task_is_live_locked (t);
	task_unlock (t);
	if (t->gate) {
		r_th_sem_post (t->gate);
	}
	if (live && t->thread) {
		r_th_kill_free (t->thread);
		t->thread = NULL;
	}
	drop_task_locked (q, t);
}

static void kill_by_id(RCorePluginSession *cps, int id) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	if (!state || !state->async) {
		return;
	}
	R2AITaskQueue *q = state->async;
	queue_lock (q);
	R2AITask *t = find_by_id (q, id);
	if (!t) {
		queue_unlock (q);
		r_cons_printf (core->cons, "No task with id %d\n", id);
		return;
	}
	kill_task_locked (q, t);
	queue_unlock (q);
	r_cons_printf (core->cons, "Killed task %d\n", id);
}

static void kill_all(RCorePluginSession *cps) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	if (!state || !state->async) {
		return;
	}
	R2AITaskQueue *q = state->async;
	queue_lock (q);
	int n = 0;
	while (!r_list_empty (q->tasks)) {
		R2AITask *t = r_list_first (q->tasks);
		kill_task_locked (q, t);
		n++;
	}
	queue_unlock (q);
	r_cons_printf (core->cons, "Killed %d task%s\n", n, n == 1? "": "s");
}

static void show_task_by_id(RCorePluginSession *cps, int id) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	if (!state || !state->async) {
		return;
	}
	R2AITaskQueue *q = state->async;
	queue_lock (q);
	R2AITask *t = find_by_id (q, id);
	if (!t) {
		queue_unlock (q);
		r_cons_printf (core->cons, "No task with id %d\n", id);
		return;
	}
	task_lock (t);
	r_cons_printf (core->cons, "id:     %d\n", t->id);
	r_cons_printf (core->cons, "kind:   %s\n", kind_name (t->kind));
	r_cons_printf (core->cons, "state:  %s\n", state_name (t->state));
	r_cons_printf (core->cons, "title:  %s\n", t->title? t->title: "");
	r_cons_printf (core->cons, "model:  %s\n", t->model? t->model: "");
	r_cons_printf (core->cons, "prov:   %s\n", t->provider? t->provider: "");
	r_cons_printf (core->cons, "steps:  %d\n", t->steps);
	r_cons_printf (core->cons, "age:    %ds\n", (int) (time (NULL) - t->created));
	if (t->pending_tool_name) {
		r_cons_printf (core->cons, "tool:   %s %s\n", t->pending_tool_name, t->pending_tool_args? t->pending_tool_args: "");
	}
	if (t->error) {
		r_cons_printf (core->cons, "error:  %s\n", t->error);
	}
	const char *out = r_strbuf_get (t->output);
	if (!R_STR_ISEMPTY (out)) {
		r_cons_printf (core->cons, "output:\n%s", out);
		if (!r_str_endswith (out, "\n")) {
			r_cons_newline (core->cons);
		}
	}
	task_unlock (t);
	queue_unlock (q);
}

static void show_last_task(RCorePluginSession *cps) {
	RCore *core = cps->core;
	R2AI_State *state = cps->data;
	if (!state || !state->async) {
		return;
	}
	R2AITaskQueue *q = state->async;
	queue_lock (q);
	R2AITask *t = r_list_last (q->tasks);
	int id = t? t->id: 0;
	queue_unlock (q);
	if (!id) {
		r_cons_printf (core->cons, "No async tasks\n");
		return;
	}
	show_task_by_id (cps, id);
}

// clang-format off
static RCoreHelpMessage help_msg_r2ai_s = {
	"Usage:", "r2ai", " -s[subcmd]",
	"r2ai", " -s", "list async tasks and completed output",
	"r2ai", " -s?", "show this help",
	"r2ai", " -sj", "list tasks as json, including completed output",
	"r2ai", " -ss", "show details of the last created task",
	"r2ai", " -si", "interactive: handle first actionable task",
	"r2ai", " -si <id>", "interactive: handle only task <id>",
	"r2ai", " -sy <id>", "approve pending tool call for task <id>",
	"r2ai", " -sn <id>", "decline pending tool call for task <id>",
	"r2ai", " -sa", "block until all tasks finish",
	"r2ai", " -sp", "purge finished/errored/cancelled tasks",
	"r2ai", " -s <id>", "show details of task <id>",
	"r2ai", " -sk", "kill all tasks",
	"r2ai", " -sk <id>", "kill task <id>",
	NULL
};

static RCoreHelpMessage help_msg_r2ai_s_kill = {
	"r2ai", " -sk", "kill all tasks",
	"r2ai", " -sk <id>", "kill task <id>",
	NULL
};
// clang-format on

static void show_help(RCorePluginSession *cps) {
	RCore *core = cps->core;
	r_core_cmd_help (core, help_msg_r2ai_s);
}

static void purge_finished(RCorePluginSession *cps) {
	R2AI_State *state = cps->data;
	if (!state || !state->async) {
		return;
	}
	R2AITaskQueue *q = state->async;
	queue_lock (q);
	RListIter *it, *tmp;
	R2AITask *t;
	r_list_foreach_safe (q->tasks, it, tmp, t) {
		task_lock (t);
		bool drop = t->state == R2AI_TASK_COMPLETE || t->state == R2AI_TASK_ERROR || t->state == R2AI_TASK_CANCELLED;
		task_unlock (t);
		if (drop) {
			drop_task_locked (q, t);
		}
	}
	queue_unlock (q);
}

static void wait_all(RCorePluginSession *cps) {
	R2AI_State *state = cps->data;
	if (!state || !state->async) {
		return;
	}
	R2AITaskQueue *q = state->async;
	for (;;) {
		bool any = false;
		queue_lock (q);
		RListIter *it;
		R2AITask *t;
		r_list_foreach (q->tasks, it, t) {
			task_lock (t);
			bool busy = t->state == R2AI_TASK_PENDING || t->state == R2AI_TASK_RUNNING;
			task_unlock (t);
			if (busy) {
				any = true;
				break;
			}
		}
		queue_unlock (q);
		if (!any) {
			break;
		}
		r_sys_usleep (100 * 1000); /* 100ms */
	}
}

R_IPI void r2ai_async_cmd(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	const char *a = input? input: "";
	const char *arg = r_str_trim_head_ro (a + 1);
	int id = R_STR_ISEMPTY (arg)? 0: r_num_math (core->num, arg);
	switch (*a) {
	case '?':
		show_help (cps);
		break;
	case 'j':
		show_task_list (cps, true);
		break;
	case 's':
		show_last_task (cps);
		break;
	case 'i':
		interact_once (cps, id);
		break;
	case 'y':
		answer_by_id (cps, id, true);
		break;
	case 'n':
		answer_by_id (cps, id, false);
		break;
	case 'a':
		wait_all (cps);
		break;
	case 'p':
		purge_finished (cps);
		break;
	case 'k':
		if (R_STR_ISEMPTY (arg)) {
			kill_all (cps);
		} else {
			if (id > 0) {
				kill_by_id (cps, id);
			} else {
				r_core_cmd_help (core, help_msg_r2ai_s_kill);
			}
		}
		break;
	case ' ':
		if (id > 0) {
			show_task_by_id (cps, id);
		} else {
			show_task_list (cps, false);
		}
		break;
	case 0:
		show_task_list (cps, false);
		break;
	default:
		r_core_return_invalid_command (core, "-s", *a);
		break;
	}
}
