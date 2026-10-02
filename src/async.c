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

static bool is_done(R2AITaskState st) {
	return st == R2AI_TASK_COMPLETE || st == R2AI_TASK_ERROR || st == R2AI_TASK_CANCELLED;
}

static R2AITaskQueue *queue(RCorePluginSession *cps) {
	return ((R2AI_State *)cps->data)->async;
}

static void print_block(RCons *cons, const char *hdr, const char *text) {
	if (R_STR_ISEMPTY (text)) {
		return;
	}
	r_cons_printf (cons, "%s%s", hdr, text);
	if (!r_str_endswith (text, "\n")) {
		r_cons_newline (cons);
	}
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

static void pending_clear(R2AITask *t) {
	R_FREE (t->pending_tool_name);
	R_FREE (t->pending_tool_args);
	R_FREE (t->pending_tool_call_id);
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
	r_list_free (t->tools);
	free (t->title);
	free (t->query);
	free (t->system_prompt);
	free (t->model);
	free (t->provider);
	r_strbuf_free (t->output);
	free (t->error);
	pending_clear (t);
	free (t->tool_result);
	free (t);
}

static void queue_lock(R2AITaskQueue *q) {
	r_th_lock_enter (q->lock);
}
static void queue_unlock(R2AITaskQueue *q) {
	r_th_lock_leave (q->lock);
}

static void task_start(R2AITask *t) {
	task_lock (t);
	t->state = R2AI_TASK_RUNNING;
	t->started = time (NULL);
	task_unlock (t);
}

static bool cancelled(R2AITask *t) {
	task_lock (t);
	bool res = t->cancel_req;
	task_unlock (t);
	return res;
}

// terminate the worker, an earlier error reported by the llm call takes precedence
static RThreadFunctionRet finish(R2AITask *t, R2AITaskState st, char *err) {
	task_lock (t);
	if (err && !t->error) {
		t->error = err;
	} else {
		free (err);
	}
	t->state = st;
	t->finished = time (NULL);
	task_unlock (t);
	return R_TH_STOP;
}

// run one llm turn, r2ai_llmcall and the providers still read core->config
static R2AI_ChatResponse *run_llm_once(R2AITask *t) {
	char *error = NULL;
	R2AIArgs args = {
		.messages = t->messages,
		.system_prompt = t->system_prompt,
		.model = t->model,
		.provider = t->provider,
		.tools = t->tools,
		.error = &error,
	};
	R2AI_ChatResponse *res = r2ai_llmcall (t->cps, args);
	if (error) {
		task_lock (t);
		free (t->error);
		t->error = error;
		task_unlock (t);
	}
	return res;
}

static void dump_message(R2AITask *t, const R2AI_Message *m) {
	if (m->reasoning_content) {
		task_append_outputf (t, "<thinking>\n%s\n</thinking>\n", m->reasoning_content);
	}
	if (m->content) {
		task_append_outputf (t, "%s\n", m->content);
	}
}

static RThreadFunctionRet worker_query(RThread *th) {
	R2AITask *t = (R2AITask *)th->user;
	task_start (t);
	R2AI_ChatResponse *res = run_llm_once (t);
	bool ok = res && res->message;
	bool cancel = cancelled (t);
	if (ok && !cancel) {
		dump_message (t, res->message);
	}
	r2ai_chat_response_free (res);
	if (cancel) {
		return finish (t, R2AI_TASK_CANCELLED, NULL);
	}
	return ok
		? finish (t, R2AI_TASK_COMPLETE, NULL)
		: finish (t, R2AI_TASK_ERROR, strdup ("llm call returned no response"));
}

static R2AI_ToolCall *first_tool_call(const R2AI_Message *m) {
	RListIter *iter;
	R2AI_ToolCall *tc;
	r_list_foreach (m->tool_calls, iter, tc) {
		if (tc->name && tc->arguments && tc->id) {
			return tc;
		}
	}
	return NULL;
}

// hand the tool call to the main thread and block until it answers, returns false if cancelled
static bool wait_tool(R2AITask *t, const R2AI_ToolCall *tc) {
	task_lock (t);
	pending_clear (t);
	R_FREE (t->tool_result);
	t->pending_tool_name = strdup (tc->name);
	t->pending_tool_args = strdup (tc->arguments);
	t->pending_tool_call_id = strdup (tc->id);
	t->state = R2AI_TASK_WAIT_APPROVE;
	task_unlock (t);

	r_th_sem_wait (t->gate);

	task_lock (t);
	if (t->cancel_req) {
		task_unlock (t);
		return false;
	}
	R2AI_Message msg = {
		.role = "tool",
		.tool_call_id = t->pending_tool_call_id,
		.content = t->tool_result? t->tool_result: "<no output>",
	};
	r2ai_msgs_add (t->messages, &msg);
	R_FREE (t->tool_result);
	pending_clear (t);
	task_unlock (t);
	return true;
}

static RThreadFunctionRet worker_auto(RThread *th) {
	R2AITask *t = (R2AITask *)th->user;
	task_start (t);
	for (;;) {
		if (cancelled (t)) {
			return finish (t, R2AI_TASK_CANCELLED, NULL);
		}
		if (t->steps >= t->max_runs) {
			return finish (t, R2AI_TASK_ERROR, r_str_newf ("max runs (%d) reached", t->max_runs));
		}
		task_lock (t);
		t->steps++;
		task_unlock (t);

		R2AI_ChatResponse *res = run_llm_once (t);
		if (!res || !res->message) {
			r2ai_chat_response_free (res);
			return finish (t, R2AI_TASK_ERROR, strdup ("llm call returned no response"));
		}
		const R2AI_Message *m = res->message;
		dump_message (t, m);
		r2ai_msgs_add (t->messages, m);
		if (r_list_empty (m->tool_calls)) {
			r2ai_chat_response_free (res);
			return finish (t, R2AI_TASK_COMPLETE, NULL);
		}
		R2AI_ToolCall *tc = first_tool_call (m);
		bool ok = tc && wait_tool (t, tc);
		r2ai_chat_response_free (res);
		if (!ok) {
			return tc
				? finish (t, R2AI_TASK_CANCELLED, NULL)
				: finish (t, R2AI_TASK_ERROR, strdup ("llm returned an invalid tool call"));
		}
	}
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
		/* take ownership of the thread while holding the task lock */
		RThread *th = live? t->thread: NULL;
		if (th) {
			t->thread = NULL;
		}
		task_unlock (t);
		if (t->gate) {
			r_th_sem_post (t->gate);
		}
		if (th) {
			/* kill_free joins the thread: never do it under the task lock */
			r_th_kill_free (th);
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
	// resolve the system prompt here, workers must not read the config
	if (R_STR_ISEMPTY (system_prompt) && kind == R2AI_TASK_AUTO) {
		t->system_prompt = r2ai_auto_system_prompt (cps);
	} else {
		t->system_prompt = r_str_new (r2ai_system_prompt (core, system_prompt));
	}
	const char *m = r_config_get (core->config, "r2ai.model");
	const char *p = r_config_get (core->config, "r2ai.api");
	t->model = m? strdup (m): NULL;
	t->provider = p? strdup (p): NULL;
	if (kind == R2AI_TASK_AUTO) {
		RList *tools = r2ai_get_tools (core, cps->data);
		t->tools = tools? r_list_clone (tools, NULL): NULL;
		t->max_runs = r_config_get_i (core->config, "r2ai.auto.max_runs");
	}
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
	R2AITask *t = task_new (cps, kind, title, query, sysp);
	int id = queue_register (queue (cps), t);
	t->thread = r_th_new (fn, t, 0);
	if (t->thread) {
		r_th_start (t->thread);
	} else {
		finish (t, R2AI_TASK_ERROR, strdup ("failed to spawn worker"));
	}
	r_cons_printf (cps->core->cons, "[async] task %d queued (%s)\n", id, t->title);
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
	RCore *core = cps->core;
	R2AITaskQueue *q = queue (cps);
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
			print_block (core->cons, "output:\n", r_strbuf_get (t->output));
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
	R2AITaskQueue *q = queue (cps);
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
	print_block (core->cons, "", output);
	free (output);
	if (err) {
		r_cons_printf (core->cons, Color_RED "error: %s" Color_RESET "\n", err);
		free (err);
	}

	if (is_done (st)) {
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
		bool approve = yolo || r_cons_yesno (core->cons, 'y', "Run tool %s? (Y/n)", tool_name? tool_name: "?");
		answer_wait_approve (cps, t, approve, true);
	}
	free (tool_name);
	free (tool_args);
}

// lock the queue and find the task, reports and unlocks when it does not exist
static R2AITask *lookup(RCorePluginSession *cps, int id) {
	R2AITaskQueue *q = queue (cps);
	queue_lock (q);
	RListIter *it;
	R2AITask *t;
	r_list_foreach (q->tasks, it, t) {
		if (t->id == id) {
			return t;
		}
	}
	queue_unlock (q);
	r_cons_printf (cps->core->cons, "No task with id %d\n", id);
	return NULL;
}

static void answer_by_id(RCorePluginSession *cps, int id, bool approve) {
	RCore *core = cps->core;
	if (id <= 0) {
		r_cons_printf (core->cons, "Missing task id\n");
		return;
	}
	R2AITaskQueue *q = queue (cps);
	R2AITask *t = lookup (cps, id);
	if (!t) {
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
	R2AITaskQueue *q = queue (cps);
	R2AITask *t = lookup (cps, id);
	if (!t) {
		return;
	}
	kill_task_locked (q, t);
	queue_unlock (q);
	r_cons_printf (core->cons, "Killed task %d\n", id);
}

static void kill_all(RCorePluginSession *cps) {
	RCore *core = cps->core;
	R2AITaskQueue *q = queue (cps);
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
	R2AITaskQueue *q = queue (cps);
	R2AITask *t = lookup (cps, id);
	if (!t) {
		return;
	}
	task_lock (t);
	r_cons_printf (core->cons, "id:     %d\nkind:   %s\nstate:  %s\ntitle:  %s\nmodel:  %s\nprov:   %s\nsteps:  %d\nage:    %ds\n",
		t->id, kind_name (t->kind), state_name (t->state), t->title, r_str_get (t->model),
		r_str_get (t->provider), t->steps, (int) (time (NULL) - t->created));
	if (t->pending_tool_name) {
		r_cons_printf (core->cons, "tool:   %s %s\n", t->pending_tool_name, t->pending_tool_args? t->pending_tool_args: "");
	}
	if (t->error) {
		r_cons_printf (core->cons, "error:  %s\n", t->error);
	}
	print_block (core->cons, "output:\n", r_strbuf_get (t->output));
	task_unlock (t);
	queue_unlock (q);
}

static void show_last_task(RCorePluginSession *cps) {
	RCore *core = cps->core;
	R2AITaskQueue *q = queue (cps);
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
	r2ai_cmd_help (core, help_msg_r2ai_s);
}

static void purge_finished(RCorePluginSession *cps) {
	R2AITaskQueue *q = queue (cps);
	queue_lock (q);
	RListIter *it, *tmp;
	R2AITask *t;
	r_list_foreach_safe (q->tasks, it, tmp, t) {
		task_lock (t);
		bool drop = is_done (t->state);
		task_unlock (t);
		if (drop) {
			drop_task_locked (q, t);
		}
	}
	queue_unlock (q);
}

static void wait_all(RCorePluginSession *cps) {
	R2AITaskQueue *q = queue (cps);
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
				r2ai_cmd_help (core, help_msg_r2ai_s_kill);
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
